from polyswarm_api.exceptions import NoResultsException
from polyswarm_api.types import resources
from pymisp import MISPAttribute, MISPEvent, MISPObject, NewAttributeError, MISPTag
import json
import requests
import hashlib
from polyswarm_api.api import PolyswarmAPI

misperrors = {'error': 'Error'}
mispattributes = {'input': [
                            'hostname', 'domain',
                            "ip-src", "ip-dst",
                            "md5", "sha1", "sha256", "url"
                            ],
                  'format': 'misp_standard'}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '2', 'author': 'PolySwarm Team',
              'description': 'Get information from PolySwarm malware',
              'module-type': ['expansion']}

# config fields that your code expects from the site admin
moduleconfig = ["apikey", "event_limit", "community"]


class PolySwarmParser(object):
    # todo figure out how to make community optional
    def __init__(self, apikey, limit, community=None):
        self.apikey = apikey
        self.limit = limit
        self.community = community
        self.base_url = "https://www.polyswarm.com/vtapi/v2/{}/report"
        self.misp_event = MISPEvent()
        self.parsed_objects = {}
        # self.input_types_mapping = {'ip-src': self.parse_ip, 'ip-dst': self.parse_ip,
        #                             'domain': self.parse_domain, 'hostname': self.parse_domain,
        #                             'md5': self.parse_hash, 'sha1': self.parse_hash,
        #                             'sha256': self.parse_hash, 'url': self.parse_url}
        self.input_types_mapping = {
                                    'ip-src': self.parse_ip, 'ip-dst': self.parse_ip,
                                    'domain': self.parse_domain, 'hostname': self.parse_domain,
                                    'md5': self.parse_hash, 'sha1': self.parse_hash,
                                    'sha256': self.parse_hash, 'url': self.parse_url
        }

    def _raise_not_implemented(self, func):
        def fake(indic, **kwargs):
            return {'error': '{} on {} is not implemented yet'.format(func, indic)}
        return fake

    @property
    def _ps_api(self):

        return PolyswarmAPI(self.apikey, community=self.community, timeout=60)

    def query_api(self, attribute):
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        return self.input_types_mapping[self.attribute.type](self.attribute.value, recurse=True)

    def get_result(self):
        # todo this is a hack to get around parsing result
        if hasattr(self, 'raw_result'):
            return self.raw_result
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object') if (key in event and event[key])}
        return {'results': results}

    ################################################################################
    ####                         Main parsing functions                         #### # noqa
    ################################################################################

    def parse_domain(self, domain, recurse=False):

        return self.parse_url("http://{}".format(domain), recurse=recurse)

    def parse_hash(self, sample, recurse=False, uuid=None, relationship=None):
        try:
            for ai in self._ps_api.search(sample):
                #req = req.json()
                if not ai.assertions:
                    # then we need to resscan
                    self._ps_api.rescan(ai.sha256)
                ps_uuid = self.parse_ps_object(ai)
                file_attributes = []
                for hash_type, h in ai.metadata.json['hash'].items():
                    file_attributes.append({'type': hash_type, 'object_relation': hash_type,
                     'value': h})

                if file_attributes:
                    file_object = MISPObject('file')
                    for attribute in file_attributes:
                        try:
                            file_object.add_attribute(**attribute)
                        except NewAttributeError:
                            attribute['type'] = 'text'
                            file_object.add_attribute(**attribute)
                            pass
                    file_object.add_reference(ps_uuid, 'analyzed-with')
                    if uuid and relationship:
                        file_object.add_reference(uuid, relationship)
                    self.misp_event.add_object(**file_object)
                # todo more texture in errors than just status code
                return 200
        except NoResultsException:

            return 404

        return 404

    def parse_ip(self, ip, recurse=False):
        return self.parse_url("http://{}".format(ip), recurse=recurse)

    def parse_url(self, url, recurse=False, uuid=None):
        # todo we need to sha256 this and search against api
        url_h = hashlib.sha256(url.encode('utf-8'))

        feature = 'url'

        # url_object = MISPObject(feature)
        # url_object.add_attribute(feature, type=feature, value=url)
        try:
            r = self._ps_api.search(url_h.hexdigest())
            for ai in r:
                ps_uuid = self.parse_ps_object(ai)

                # ps_uuid.add_reference(ps_uuid, 'analyzed-with')
                # todo include last analysis date

                return 200
            # scans should resubmit if we dont' find url
        except NoResultsException:

            # todo config to submit if not found
            s = self._ps_api.submit(url, artifact_type=resources.ArtifactType.URL)
            ps_uuid = self.parse_ps_object(s, scan_submit=True)

            return 200

        # status_code = req.status_code
        # if req.status_code == 200:
        #     req = req.json()
        #     vt_uuid = self.parse_ps_object(req)
        #     if not recurse:
        #         feature = 'url'
        #         url_object = MISPObject(feature)
        #         url_object.add_attribute(feature, type=feature, value=url)
        #         url_object.add_reference(vt_uuid, 'analyzed-with')
        #         if uuid:
        #             url_object.add_reference(uuid, 'hosted-in')
        #         self.misp_event.add_object(**url_object)
        return 404

    ################################################################################
    ####                      Additional parsing functions                      #### # noqa
    ################################################################################

    def parse_related_urls(self, query_result, recurse, uuid=None):
        if recurse:
            for feature in ('detected_urls', 'undetected_urls'):
                if feature in query_result:
                    for url in query_result[feature]:
                        value = url['url'] if isinstance(url, dict) else url[0]
                        status_code = self.parse_url(value, False, uuid)
                        if status_code != 200:
                            return status_code
        else:
            for feature in ('detected_urls', 'undetected_urls'):
                if feature in query_result:
                    for url in query_result[feature]:
                        value = url['url'] if isinstance(url, dict) else url[0]
                        self.misp_event.add_attribute('url', value)
        return 200

    def parse_resolutions(self, resolutions, subdomains=None, uuids=None):
        domain_ip_object = MISPObject('domain-ip')
        if self.attribute.type == 'domain':
            domain_ip_object.add_attribute('domain', type='domain', value=self.attribute.value)
            attribute_type, relation, key = ('ip-dst', 'ip', 'ip_address')
        else:
            domain_ip_object.add_attribute('ip', type='ip-dst', value=self.attribute.value)
            attribute_type, relation, key = ('domain', 'domain', 'hostname')
        for resolution in resolutions:
            domain_ip_object.add_attribute(relation, type=attribute_type, value=resolution[key])
        if subdomains:
            for subdomain in subdomains:
                attribute = MISPAttribute()
                attribute.from_dict(**dict(type='domain', value=subdomain))
                self.misp_event.add_attribute(**attribute)
                domain_ip_object.add_reference(attribute.uuid, 'subdomain')
        if uuids:
            for uuid in uuids:
                domain_ip_object.add_reference(uuid, 'sibling-of')
        self.misp_event.add_object(**domain_ip_object)
        return domain_ip_object.uuid

    def parse_siblings(self, domain):
        attribute = MISPAttribute()
        attribute.from_dict(**dict(type='domain', value=domain))
        self.misp_event.add_attribute(**attribute)
        return attribute.uuid

    def parse_ps_object(self, ai, scan_submit=False):
        if ai:
            ps_object = MISPObject('polyswarm-report')
            ps_object.add_attribute('permalink', type='link', value=ai.permalink)
            ps_object.add_attribute('polyscore', type='float', value=ai.polyscore)

            if ai.type == "FILE":

                [ps_object.add_attribute('filename', type='filename', value=fn)for fn in ai.filenames]
                if ai.metadata.urls:
                    [ps_object.add_attribute('url', type='url', value=fn)for fn in ai.metadata.urls[:10]]
                ps_object.add_attribute('filesize', type='size-in-bytes', value=ai.size)
                ps_object.add_attribute('mime-type', type='mime-type', value=ai.mimetype)
                # todo allow for limit configure
                [ps_object.add_attribute('domain', type='domain', value=fn)for fn in ai.metadata.domains[:10]]
                # todo get below modfied, figure out malware family name
                # todo add IP




            elif ai.type == "URL":
                # todo dns and submit for scanning?
                # todo if we just submitted?
                #
                pass

            # here we cover the case where we just submitted a rescan
            if scan_submit:
                self._add_in_progress_scan_attribute(ai, ps_object)

            ps_object.add_attribute("first_seen", type='datetime', value=ai.first_seen)
            ps_object.add_attribute("last_seen", type='datetime', value=ai.last_seen)
            detection_ratio = '{}/{}'.format(len(ai.detections), len(ai.assertions))
            ps_object.add_attribute('detection-ratio', type='text', value=detection_ratio)

            ps_object.add_attribute('malicious_detections', type='counter', value=len(ai.detections))
            ps_object.add_attribute('total_assertions', type='counter', value=len(ai.assertions))

            self.misp_event.add_object(**ps_object)
            return ps_object.uuid

    def _add_in_progress_scan_attribute(self, ai, ps_object):
        request_to_not_exec_just_get_url = self._ps_api.generator.lookup_uuid(ai.id)
        # this gets tagged with in process for later
        mt = MISPTag()
        tags = ["workflow:state='incomplete'"]
        sub_o = ps_object.add_attribute('scan-submission', type='link',
                                        value=request_to_not_exec_just_get_url.request_parameters['url'], Tag=tags, )


def parse_error(status_code):
    status_mapping = {204: 'PolySwarm request rate limit exceeded.',
                      400: 'Incorrect request, please check the arguments.',
                      403: 'You don\'t have enough privileges to make the request.'}
    if status_code in status_mapping:
        return status_mapping[status_code]
    return "PolySwarm may not be accessible."


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('config') or not request['config'].get('apikey'):
        misperrors['error'] = "A PolySwarm api key is required for this module."
        return misperrors
    event_limit = request['config'].get('event_limit')
    if not isinstance(event_limit, int):
        event_limit = 5
    parser = PolySwarmParser(request['config']['apikey'], event_limit)
    attribute = request['attribute']
    status = parser.query_api(attribute)
    if status != 200:
        misperrors['error'] = parse_error(status)
        return misperrors
    return parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

