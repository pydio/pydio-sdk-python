# -*- coding: utf-8 -*-
#  Copyright 2007-2016 Charles du Jeu - Abstrium SAS <team (at) pydio.com>
#  This file is part of Pydio.
#
#  Pydio is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Pydio is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with Pydio.  If not, see <http://www.gnu.org/licenses/>.
#
#  The latest code can be found at <http://pyd.io/>.
#

import urllib
import json
import hmac
import random
import unicodedata
import platform
from hashlib import sha256
from hashlib import sha1
from urlparse import urlparse
import math
import threading
import websocket
import ssl
import boto3
from boto3.s3.transfer import TransferConfig
from requests.exceptions import ConnectionError, RequestException
import keyring
from keyring.errors import PasswordSetError
import xml.etree.ElementTree as ET
from pydio_exceptions import PydioSdkException, PydioSdkBasicAuthException, PydioSdkTokenAuthException, \
    PydioSdkQuotaException, PydioSdkPermissionException, PydioSdkTokenAuthNotSupportedException, PydioSdkDefaultException
from util import *
try:
    from pydio.utils.functions import hashfile
    from pydio import TRANSFER_RATE_SIGNAL, TRANSFER_CALLBACK_SIGNAL
    from pydio.utils import i18n
    _ = i18n.language.ugettext
except ImportError:
    try:
        from utils.functions import hashfile
        from utils import i18n
        _ = i18n.language.ugettext
    except ImportError:
        from util import hashfile
    try:
        TRANSFER_RATE_SIGNAL
    except NameError:
        TRANSFER_RATE_SIGNAL = 'transfer_rate'
        TRANSFER_CALLBACK_SIGNAL = 'transfer_callback'
try:
    _
except NameError:
    def _(message):
        """ Fake i18n patch """
        return message

""" For request debugging
from httplib import HTTPConnection
HTTPConnection.debuglevel = 1
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
#"""
"""
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
#"""

PYDIO_SDK_MAX_UPLOAD_PIECES = 40 * 1024 * 1024


class PydioSdk():

    def __init__(self, url='', ws_id='', remote_folder='', user_id='', auth=(), device_id='python_client',
                 skip_ssl_verify=False, proxies=None, timeout=20):
        self.ws_id = ws_id
        self.device_id = device_id
        self.verify_ssl = not skip_ssl_verify
        if self.verify_ssl and "REQUESTS_CA_BUNDLE" in os.environ:
            self.verify_ssl = os.environ["REQUESTS_CA_BUNDLE"]


        self.base_url = url.rstrip('/') + '/api/'
        self.url = url.rstrip('/') + '/api/' + ws_id
        self.remote_folder = remote_folder
        self.user_id = user_id
        self.interrupt_tasks = False
        self.upload_max_size = PYDIO_SDK_MAX_UPLOAD_PIECES
        self.rsync_server_support = False
        self.stat_slice_number = 200
        self.stick_to_basic = False
        if user_id:
            self.auth = (user_id, keyring.get_password(url, user_id))
        else:
            self.auth = auth
        self.rsync_supported = False
        self.proxies = proxies
        self.timeout = timeout
        # for websockets logic, sdk's state
        self.should_fetch_changes = False
        self.remote_repo_id = None
        self.websocket_server_data = {}
        self.waiter = None
        self.jwtNotSupported = False
        self.jwt = None
        self.jwtExpiration = None

    def set_server_configs(self, configs):
        """
        Server specific capacities and limitations, provided by the server itself
        :param configs: dict()
        :return:
        """
        if 'UPLOAD_MAX_SIZE' in configs and configs['UPLOAD_MAX_SIZE']:
            self.upload_max_size = min(int(float(configs['UPLOAD_MAX_SIZE'])), PYDIO_SDK_MAX_UPLOAD_PIECES)
        if 'RSYNC_SUPPORTED' in configs and configs['RSYNC_SUPPORTED'] == "true":
            self.rsync_server_support = True
        #self.upload_max_size = 8*1024*1024;
        if 'RSYNC_SUPPORTED' in configs:
            self.rsync_supported = configs['RSYNC_SUPPORTED'] == 'true'
        pass

    def set_interrupt(self):
        self.interrupt_tasks = True

    def remove_interrupt(self):
        self.interrupt_tasks = False

    def urlencode_normalized(self, unicode_path):
        """
        Make sure the urlencoding is consistent between various platforms
        E.g, we force the accented chars to be encoded as one char, not the ascci + accent.
        :param unicode_path:
        :return:
        """
        if platform.system() == 'Darwin':
            try:
                test = unicodedata.normalize('NFC', unicode_path)
                unicode_path = test
            except ValueError as e:
                logging.exception(e)
                pass
        return urllib.pathname2url(unicode_path.encode('utf-8'))

    def normalize(self, unicode_path):
        try:
            test = unicodedata.normalize('NFC', unicode_path)
            return test
        except ValueError as e:
            logging.exception(e)
            return unicode_path

    def normalize_reverse(self, unicode_path):
        if platform.system() == 'Darwin':
            try:
                test = unicodedata.normalize('NFD', unicode_path)
                return test
            except ValueError as e:
                logging.exception(e)
                return unicode_path
        else:
            return unicode_path

    def set_tokens(self, tokens):
        try:
            user = self.user_id + '-token'
            password = tokens['t'] + ':' + tokens['p']
            keyring.set_password(self.base_url, user, password)
        except PasswordSetError as pe:
            logging.info("Failed to set_tokens " + self.base_url + " " + self.ws_id)
            logging.exception(pe)
            logging.error(_("Cannot store tokens in keychain, there might be an OS permission issue!"))

    def get_tokens(self, from_keyring=False):
        k_tok = keyring.get_password(self.base_url, self.user_id + '-token')
        if k_tok:
            parts = k_tok.split(':')
            tokens = {'t': parts[0], 'p': parts[1]}
            return tokens
        else:
            return False

    def basic_authenticate(self):
        """
        Use basic-http authenticate to get a key/pair token instead of passing the
        users credentials at each requests
        :return:dict()
        """
        # only authenticate if you're the token latest owner RACE CONDITION of DEATH
        tokens = self.get_tokens()
        org_tokens = self.get_tokens()
        url = self.base_url + 'pydio/keystore_generate_auth_token/' + self.device_id
        resp = requests.get(url=url, auth=self.auth, verify=self.verify_ssl, proxies=self.proxies)
        if resp.status_code == 401:
            raise PydioSdkBasicAuthException(_('Authentication Error'))

        # If content is empty (but not error status code), the token based auth may not be active
        # We should switch to basic
        if resp.content == '':
            raise PydioSdkTokenAuthNotSupportedException("token_auth")

        try:
            tokens = json.loads(resp.content)
        except ValueError as v:
            raise PydioSdkException("basic_auth", "", "Cannot parse JSON result: " + resp.content + "")
        keyring_tokens = self.get_tokens()  # make sure the token wasn't updated during this update
        if not keyring_tokens or (keyring_tokens['t'] == org_tokens['t'] and keyring_tokens['p'] == org_tokens['p']):
            self.set_tokens(tokens)
        else:
            tokens = keyring_tokens
        return tokens

    def perform_basic(self, url, request_type='get', data=None, files=None, headers=None, stream=False, with_progress=False):
        """
        :param headers:
        :param url: str url to query
        :param request_type: str http method, default is "get"
        :param data: dict query parameters
        :param files: dict files, described as {'fieldname':'path/to/file'}
        :param stream: bool get response as a stream
        :param with_progress: dict an object that can be updated with various progress data
        :return: Http response
        """
        if request_type == 'get':
            try:
                resp = requests.get(url=url, stream=stream, timeout=self.timeout, verify=self.verify_ssl, headers=headers,
                                    auth=self.auth, proxies=self.proxies)
            except ConnectionError as e:
                raise

        elif request_type == 'post':
            if not data:
                data = {}
            if files:
                resp = self.upload_file_with_progress(url, dict(**data), files, stream, with_progress,
                                                      max_size=self.upload_max_size, auth=self.auth)
            else:
                resp = requests.post(
                    url=url,
                    data=data,
                    stream=stream,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    headers=headers,
                    auth=self.auth,
                    proxies=self.proxies)
        else:
            raise PydioSdkTokenAuthException(_("Unsupported HTTP method"))

        if resp.status_code == 401:
            raise PydioSdkTokenAuthException(_("Authentication Exception"))
        return resp


    def perform_with_tokens(self, token, private, url, request_type='get', data=None, files=None, headers=None, stream=False,
                            with_progress=False):
        """

        :param headers:
        :param token: str the token.
        :param private: str private key associated to token
        :param url: str url to query
        :param request_type: str http method, default is "get"
        :param data: dict query parameters
        :param files: dict files, described as {'fieldname':'path/to/file'}
        :param stream: bool get response as a stream
        :param with_progress: dict an object that can be updated with various progress data
        :return: Http response
        """
        nonce = sha1(str(random.random())).hexdigest()
        uri = urlparse(url).path.rstrip('/')
        msg = uri + ':' + nonce + ':' + private
        the_hash = hmac.new(str(token), str(msg), sha256)
        auth_hash = nonce + ':' + the_hash.hexdigest()

        if request_type == 'get':
            auth_string = 'auth_token=' + token + '&auth_hash=' + auth_hash
            if '?' in url:
                url += '&' + auth_string
            else:
                url += '?' + auth_string
            try:
                resp = requests.get(url=url, stream=stream, timeout=self.timeout, verify=self.verify_ssl,
                                    headers=headers, proxies=self.proxies)
            except ConnectionError as e:
                raise

        elif request_type == 'post':
            if not data:
                data = {}
            data['auth_token'] = token
            data['auth_hash'] = auth_hash
            if files:
                resp = self.upload_file_with_progress(url, dict(**data), files, stream, with_progress,
                                                 max_size=self.upload_max_size)
            else:
                resp = requests.post(
                    url=url,
                    data=data,
                    stream=stream,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    headers=headers,
                    proxies=self.proxies)
        else:
            raise PydioSdkTokenAuthException(_("Unsupported HTTP method"))

        if resp.status_code == 401:
            raise PydioSdkTokenAuthException(_("Authentication Exception"))
        return resp

    def perform_request(self, url, type='get', data=None, files=None, headers=None, stream=False, with_progress=False):
        """
        Perform an http request.
        There's a one-time loop, as it first tries to use the auth tokens. If the the token auth fails, it may just
        mean that the token key/pair is expired. So we try once to get fresh new tokens with basic_http auth and
        re-run query with new tokens.

        :param headers:
        :param url: str url to query
        :param type: str http method, default is "get"
        :param data: dict query parameters
        :param files: dict files, described as {'filename':'path/to/file'}
        :param stream: bool get response as a stream
        :param with_progress: dict an object that can be updated with various progress data
        :return:
        """
        # We know that token auth is not supported anyway
        #logging.info(url)
        if self.stick_to_basic:
            return self.perform_basic(url, request_type=type, data=data, files=files, headers=headers, stream=stream,
                                          with_progress=with_progress)

        tokens = self.get_tokens()
        if not tokens:
            try:
                tokens = self.basic_authenticate()
            except PydioSdkTokenAuthNotSupportedException as pne:
                logging.info('Switching to permanent basic auth, as tokens were not correctly received. This is not '
                             'good for performances, but might be necessary for session credential based setups.')
                self.stick_to_basic = True
                return self.perform_basic(url, request_type=type, data=data, files=files, headers=headers, stream=stream,
                                          with_progress=with_progress)

            return self.perform_with_tokens(tokens['t'], tokens['p'], url, type, data, files,
                                            headers=headers, stream=stream)
        else:
            try:
                resp = self.perform_with_tokens(tokens['t'], tokens['p'], url, type, data, files, headers=headers,
                                                stream=stream, with_progress=with_progress)
                return resp
            except requests.exceptions.ConnectionError:
                raise
            except PydioSdkTokenAuthException as pTok:
                # Token exception -> Authenticate
                try:
                    tokens = self.basic_authenticate()
                except PydioSdkTokenAuthNotSupportedException:
                    self.stick_to_basic = True
                    logging.info('Switching to permanent basic auth, as tokens were not correctly received. This is not '
                                 'good for performances, but might be necessary for session credential based setups.')
                    return self.perform_basic(url, request_type=type, data=data, files=files, headers=headers, stream=stream,
                                              with_progress=with_progress)
                try:
                    return self.perform_with_tokens(tokens['t'], tokens['p'], url, type, data, files,
                                                    headers=headers, stream=stream, with_progress=with_progress)
                except PydioSdkTokenAuthException as secTok:
                    logging.exception("(2) Token problem " + self.base_url + " " + self.ws_id)
                    raise secTok

    def check_basepath(self):
        if self.remote_folder:
            stat = self.stat('')
            return True if stat else False
        else:
            return True

    def changes(self, last_seq):
        """
        Get the list of changes detected on server since a given sequence number

        :param last_seq:int
        :return:list a list of changes
        """
        url = self.url + '/changes/' + str(last_seq)
        #logging.info(url)
        if self.remote_folder:
            url += '?filter=' + self.remote_folder
        try:
            resp = self.perform_request(url=url)
        except requests.exceptions.ConnectionError:
            raise
        try:
            if platform.system() == "Darwin":
                return json.loads(self.normalize_reverse(resp.content.decode('unicode_escape')))
            else:
                return json.loads(self.normalize(resp.content.decode('unicode_escape')))
        except ValueError as v:
            logging.exception(v)
            raise Exception(_("Invalid JSON value received while getting remote changes. Is the server correctly configured?"))

    def changes_stream(self, last_seq, callback):
        """
        Get the list of changes detected on server since a given sequence number

        :param last_seq:int
        :change_store: AbstractChangeStore
        :return:list a list of changes
        """
        if last_seq == 0:
            perform_flattening = "true"
        else:
            perform_flattening = "false"
        url = self.url + '/changes/' + str(last_seq) + '/?stream=true'
        if self.remote_folder:
            url += '&filter=' + self.remote_folder
        url += '&flatten=' + perform_flattening

        resp = self.perform_request(url=url, stream=True)
        info = dict()
        info['max_seq'] = last_seq
        for line in resp.iter_lines(chunk_size=512, delimiter="\n"):
            if line:
                if str(line).startswith('LAST_SEQ'):
                    #call the merge function with NULL row
                    callback('remote', None, info)
                    return int(line.split(':')[1])
                else:
                    try:
                        if platform.system() == "Darwin":
                            line = self.normalize_reverse(line.decode('unicode_escape'))
                        one_change = json.loads(line, strict=False)
                        node = one_change.pop('node')
                        one_change = dict(node.items() + one_change.items())
                        if not one_change.has_key('target') or not one_change.has_key('source'):
                            continue
                        callback('remote', one_change, info)

                    except ValueError as v:
                        if str(line).count("message type=\"ERROR\""):
                            import re
                            # Remove XML tags
                            text = re.sub('<[^<]+>', '', line.decode('unicode_escape'))
                            raise PydioSdkDefaultException(text)
                        logging.error('Invalid JSON Response, line was ' + str(line))
                        raise Exception(_('Invalid JSON value received while getting remote changes'))
                    except Exception as e:
                        logging.exception(e)
                        raise e

    def stat(self, path, with_hash=False, partial_hash=None):
        """
        Equivalent of the local fstat() on the remote server.
        :param path: path of node from the workspace root
        :param with_hash: stat result can be enriched with the node hash
        :return:dict a list of key like
        {
            dev: 16777218,
            ino: 4062280,
            mode: 16895,
            nlink: 15,
            uid: 70,
            gid: 20,
            rdev: 0,
            size: 510,
            atime: 1401915891,
            mtime: 1399883020,
            ctime: 1399883020,
            blksize: 4096,
            blocks: 0
        }
        """
        if self.interrupt_tasks:
            raise PydioSdkException("stat", path=path, detail=_('Task interrupted by user'))

        path = self.remote_folder + path
        action = '/stat_hash' if with_hash else '/stat'
        try:
            url = self.url + action + self.urlencode_normalized(path)
            if partial_hash:
                h = {'range': 'bytes=%i-%i' % (partial_hash[0], partial_hash[1])}
                resp = self.perform_request(url, headers=h)
            else:
                resp = self.perform_request(url)
            try:
                content = resp.content
                if platform.system() == "Darwin":
                    content = self.normalize_reverse(content.decode('unicode_escape'))
                data = json.loads(content, strict=False)
            except ValueError as ve:
                logging.exception(ve)
                if content:
                    logging.info(content)
                return False
            logging.debug("data: %s" % data)
            if not data:
                return False
            if len(data) > 0 and 'size' in data:
                return data
            else:
                return False
        except requests.exceptions.ConnectionError as ce:
            logging.error("Connection Error " + str(ce))
        except requests.exceptions.Timeout as ce:
            logging.error("Timeout Error " + str(ce))
        except Exception, ex:
            logging.exception(ex)
            logging.warning("Stat failed", exc_info=ex)
        return False

    def bulk_stat(self, pathes, result=None, with_hash=False):
        """
        Perform a stat operation (see self.stat()) but on a set of nodes. Very important to use that method instead
        of sending tons of small stat requests to server. To keep POST content reasonable, pathes will be sent 200 by
        200.

        :param pathes: list() of node pathes
        :param result: dict() an accumulator for the results
        :param with_hash: bool whether to ask for files hash or not (md5)
        :return:
        """
        if self.interrupt_tasks:
            raise PydioSdkException("stat", path=pathes[0], detail=_('Task interrupted by user'))

        from requests.exceptions import Timeout
        # NORMALIZE PATHES FROM START
        pathes = map(lambda p: self.normalize(p), pathes)

        action = '/stat_hash' if with_hash else '/stat'
        data = dict()
        maxlen = min(len(pathes), self.stat_slice_number)
        if platform.system() == "Darwin":
            clean_pathes = map(lambda t: self.remote_folder + t.replace('\\', '/'), filter(lambda x: self.normalize_reverse(x) != '', pathes[:maxlen]))
        else:
            clean_pathes = map(lambda t: self.remote_folder + t.replace('\\', '/'), filter(lambda x: x != '', pathes[:maxlen]))
        data['nodes[]'] = map(lambda p: self.normalize(p), clean_pathes)
        url = self.url + action + self.urlencode_normalized(clean_pathes[0])
        try:
            resp = self.perform_request(url, type='post', data=data)
        except Timeout:
            if self.stat_slice_number < 20:
                raise
            self.stat_slice_number = int(math.floor(self.stat_slice_number / 2))
            logging.info('Reduce bulk stat slice number to %d', self.stat_slice_number)
            return self.bulk_stat(pathes, result=result, with_hash=with_hash)

        try:
            # Possible Composed, Decomposed utf-8 is handled later...
            data = json.loads(resp.content, strict=False)
        except ValueError:
            logging.debug("url: %s" % url)
            logging.info("resp.content: %s" % resp.content)
            raise

        if len(pathes) == 1:
            englob = dict()
            englob[self.remote_folder + pathes[0]] = data
            data = englob
        if result:
            replaced = result
        else:
            replaced = dict()
        for (p, stat) in data.items():
            if self.remote_folder:
                p = p[len(self.remote_folder):]
                #replaced[os.path.normpath(p)] = stat
            p1 = os.path.normpath(p)
            p2 = os.path.normpath(self.normalize_reverse(p))
            p3 = p
            p4 = self.normalize_reverse(p)
            if p2 in pathes:
                replaced[p2] = stat
                pathes.remove(p2)
            elif p1 in pathes:
                replaced[p1] = stat
                pathes.remove(p1)
            elif p3 in pathes:
                replaced[p3] = stat
                pathes.remove(p3)
            elif p4 in pathes:
                replaced[p4] = stat
                pathes.remove(p4)
            else:
                #pass
                logging.info('Fatal charset error, cannot find files (%s, %s, %s, %s) in %s' % (repr(p1), repr(p2), repr(p3), repr(p4), repr(pathes),))
                raise PydioSdkException('bulk_stat', p1, "Encoding problem, failed emptying bulk_stat, "
                                                         "exiting to avoid infinite loop")
        if len(pathes):
            self.bulk_stat(pathes, result=replaced, with_hash=with_hash)
        return replaced

    def mkdir(self, path):
        """
        Create a directory of the server
        :param path: path of the new directory to create
        :return: result of the server query, see API
        """
        url = self.url + '/mkdir' + self.urlencode_normalized((self.remote_folder + path))
        resp = self.perform_request(url=url)
        self.is_pydio_error_response(resp)
        return resp.content

    def bulk_mkdir(self, pathes):
        """
        Create many directories at once
        :param pathes: a set of directories to create
        :return: content of the response
        """
        data = dict()
        data['ignore_exists'] = 'true'
        data['nodes[]'] = map(lambda t: self.normalize(self.remote_folder + t), filter(lambda x: x != '', pathes))
        url = self.url + '/mkdir' + self.urlencode_normalized(self.remote_folder + pathes[0])
        resp = self.perform_request(url=url, type='post', data=data)
        self.is_pydio_error_response(resp)
        return resp.content

    def mkfile(self, path, localstat=None):
        """
        Create an empty file on the server
        :param path: node path
        :return: result of the server query
        """
        resp = None
        if localstat is not None:
            if not self.stat(path) and localstat['size'] == 0:
                url = self.url + '/mkfile' + self.urlencode_normalized((self.remote_folder + path)) + '?force=true'
                resp = self.perform_request(url=url)
                self.is_pydio_error_response(resp)
                return resp.content
        else:
            url = self.url + '/mkfile' + self.urlencode_normalized((self.remote_folder + path)) + '?force=true'
            resp = self.perform_request(url=url)
            self.is_pydio_error_response(resp)
        if resp and resp.content:
            return resp.content
        return ''

    def rename(self, source, target):
        """
        Rename a path to another. Will decide automatically to trigger a rename or a move in the API.
        :param source: origin path
        :param target: target path
        :return: response of the server
        """
        if os.path.dirname(source) == os.path.dirname(target):
            # logging.debug("[sdk remote] /rename " + source + " to " + target)
            url = self.url + '/rename'
            data = dict(file=self.normalize(self.remote_folder + source).encode('utf-8'),
                        dest=self.normalize(self.remote_folder + target).encode('utf-8'))
        elif os.path.split(source)[-1] == os.path.split(target)[-1]:
            # logging.debug("[sdk remote] /move " + source + " into " + target)
            url = self.url + '/move'
            data = dict(file=(self.normalize(self.remote_folder + source)).encode('utf-8'),
                        dest=os.path.dirname((self.normalize(self.remote_folder + target).encode('utf-8'))))
        else:
            # logging.debug("[remote sdk debug] MOVEANDRENAME " + source + " " + target)
            url1 = self.url + '/rename'
            url2 = self.url + '/move'
            tmpname = os.path.join(self.remote_folder, os.path.join(*os.path.split(source)[:-1]), os.path.split(target)[-1])
            data1 = dict(file=self.normalize(self.remote_folder + source).encode('utf-8'),
                         dest=self.normalize(tmpname).encode('utf-8'))
            data2 = dict(file=self.normalize(tmpname).encode('utf-8'),
                         dest=os.path.dirname((self.normalize(self.remote_folder + target).encode('utf-8'))))
            resp1 = self.perform_request(url=url1, type='post', data=data1)
            resp2 = self.perform_request(url=url2, type='post', data=data2)
            self.is_pydio_error_response(resp1)
            self.is_pydio_error_response(resp2)
            return resp1.content + resp2.content
        resp = self.perform_request(url=url, type='post', data=data)
        self.is_pydio_error_response(resp)
        return resp.content

    def lsync(self, source=None, target=None, copy=False):
        """
        Rename a path to another. Will decide automatically to trigger a rename or a move in the API.
        :param source: origin path
        :param target: target path
        :return: response of the server
        """
        url = self.url + '/lsync'
        data = dict()
        if source:
            data['from'] = self.normalize(self.remote_folder + source).encode('utf-8')
        if target:
            data['to'] = self.normalize(self.remote_folder + target).encode('utf-8')
        if copy:
            data['copy'] = 'true'
        resp = self.perform_request(url=url, type='post', data=data)
        self.is_pydio_error_response(resp)
        return resp.content

    def delete(self, path):
        """
        Delete a resource on the server
        :param path: node path
        :return: response of the server
        """
        url = self.url + '/delete' + self.urlencode_normalized((self.remote_folder + path))
        data = dict(file=self.normalize(self.remote_folder + path).encode('utf-8'))
        resp = self.perform_request(url=url, type='post', data=data)
        self.is_pydio_error_response(resp)
        return resp.content

    def load_server_configs(self):
        """
        Load the plugins from the registry and parse some of the exposed parameters of the plugins.
        Currently supports the uploaders paramaters, and the filehasher.
        :return: dict() parsed configs
        """
        url = self.base_url + 'pydio/state/plugins?format=json'
        #logging.info(url)
        resp = self.perform_request(url=url)
        server_data = dict()
        try:
            data = json.loads(resp.content)
            plugins = data['plugins']
            for p in plugins['ajxpcore']:
                if p['@id'] == 'core.uploader':
                    if 'plugin_configs' in p and 'property' in p['plugin_configs']:
                        properties = p['plugin_configs']['property']
                        for prop in properties:
                            server_data[prop['@name']] = prop['$']
            if "meta" in plugins:
                for p in plugins['meta']:
                    if p['@id'] == 'meta.filehasher':
                        if 'plugin_configs' in p and 'property' in p['plugin_configs']:
                            properties = p['plugin_configs']['property']
                            if '@name' in properties:
                                server_data[properties['@name']] = properties['$']
                            else:
                                for prop in properties:
                                    server_data[prop['@name']] = prop['$']
                #logging.info(json.dumps(data['plugins']['ajxp_plugin'], indent=4))
                #logging.info(json.dumps(plugins['ajxp_plugin'], indent=4))
                #if hasattr(plugins, 'ajxp_plugin'):
                # Get websocket information... #yolo
                for p in data['plugins']['ajxp_plugin']:
                    try:
                        if p['@id'] == 'core.mq':
                            for prop in p['plugin_configs']['property']:
                                if prop['@name'] not in ['BOOSTER_WS_ADVANCED', 'BOOSTER_UPLOAD_ADVANCED']:
                                    self.websocket_server_data[prop['@name']] = prop['$'].replace('\\', '').replace('"', '')
                                else:
                                    self.websocket_server_data[prop['@name']] = json.loads(prop['$'].replace('\\', ''))
                    except KeyError:
                        pass
                #logging.info(url + " : " + str(self.websocket_server_data))
            else:
                logging.info("Meta was not found in plugin information.")
        except KeyError as e:
            logging.exception(e)
        return server_data

    def upload_url(self, path):
        """
        Generate a signed URI to upload to depending on supported server features
        :param file_path:
        :return: the url on which the file should be uploaded to
        """
        # TEMPORARILY DISABLE
        return self.url + '/upload/put' + self.urlencode_normalized((self.remote_folder + os.path.dirname(path)))
        # BOOSTER_MAIN_SECURE or self.url ?
        url = None
        file_path = self.urlencode_normalized(path)
        try:
            host, port, prot = None, None, 'http'
            if 'BOOSTER_UPLOAD_ADVANCED' in self.websocket_server_data and \
                'UPLOAD_ACTIVE' in self.websocket_server_data and \
                self.websocket_server_data['UPLOAD_ACTIVE'] == 'true':
                if 'booster_upload_advanced' in self.websocket_server_data['BOOSTER_UPLOAD_ADVANCED'] and \
                        self.websocket_server_data['BOOSTER_UPLOAD_ADVANCED']['booster_upload_advanced'] == 'custom':
                        if 'UPLOAD_HOST' in self.websocket_server_data:
                            host = self.websocket_server_data['UPLOAD_HOST']
                        if 'UPLOAD_PORT' in self.websocket_server_data:
                            port = self.websocket_server_data['UPLOAD_PORT']
                else:
                    host = self.websocket_server_data['BOOSTER_MAIN_HOST']
                    port = self.websocket_server_data['BOOSTER_MAIN_PORT']
                if 'BOOSTER_MAIN_SECURE' in self.websocket_server_data and \
                        self.websocket_server_data['BOOSTER_MAIN_SECURE'] == 'true':
                        prot = 'https'
                if 'UPLOAD_SECURE' in self.websocket_server_data and \
                        self.websocket_server_data['UPLOAD_SECURE'] == 'true':
                        prot = 'https'
            if self.remote_repo_id is None:
                self.remote_repo_id = self.get_user_rep()
            nonce = sha1(str(random.random())).hexdigest()
            uri = '/api/' + self.remote_repo_id + '/upload/put' + os.path.dirname(file_path)
            #logging.info("URI: " + uri)
            tokens = self.get_tokens()
            msg = uri + ':' + nonce + ':' + tokens['p']
            the_hash = hmac.new(str(tokens['t']), str(msg), sha256)
            auth_hash = nonce + ':' + the_hash.hexdigest()
            mess = 'auth_hash=' + auth_hash + '&auth_token=' + tokens['t']
            url = prot + "://" + host + ":" + port + "/" + self.websocket_server_data['UPLOAD_PATH'] + '/' + self.remote_repo_id + file_path + '?' + mess
            #logging.info('UPLOAD TYPE 2')
        except Exception as e:
            logging.exception(e)
            url = self.url + '/upload/put' + self.urlencode_normalized((self.remote_folder + os.path.dirname(path)))
        return url

    def upload_and_hashstat(self, local, local_stat, path, status_handler, callback_dict=None, max_upload_size=-1):
        """
        Upload a file to the server.
        :param local: file path
        :param local_stat: stat of the file
        :param path: target path on the server
        :param callback_dict: an dict that can be fed with progress data
        :param max_upload_size: a known or arbitrary upload max size. If the file file is bigger, it will be
        chunked into many POST requests
        :return: Server response
        """
        if not local_stat:
            raise PydioSdkException('upload', path, _('Local file to upload not found!'), 1404)
        if local_stat['size'] == 0 and not self.stat(path):
            self.mkfile(path)
            new = self.stat(path)
            if not new or not (new['size'] == local_stat['size']):
                raise PydioSdkException('upload', path, _('File not correct after upload (expected size was 0 bytes)'))
            return True
        # Wait for file size to be stable
        with open(local, 'r') as f:
            f.seek(0, 2)  # end of file
            size = f.tell()
            while True:
                f.seek(0, 2)  # end of file
                if size == f.tell():
                    break
                else:
                    logging.info(" Waiting for file write to end...")
                    time.sleep(.8)
                size = f.tell()
        existing_part = False
        if (self.upload_max_size - 4096) < local_stat['size']:
            self.has_disk_space_for_upload(path, local_stat['size'])
            existing_part = self.stat(path+'.dlpart', True)
        dirpath = os.path.dirname(path)
        if dirpath and dirpath != '/':
            folder = self.stat(dirpath)
            if not folder:
                self.mkdir(os.path.dirname(path))
        url = self.upload_url(path)
        files = {
            'userfile_0': local
        }
        if existing_part:
            files['existing_dlpart'] = existing_part

        data = {
            'force_post': 'true',
            'xhr_uploader': 'true',
            'normalized_path': self.normalize(self.remote_folder + path),
            'urlencoded_filename': self.urlencode_normalized(os.path.basename(path))
        }
        resp = None
        #logging.info(data)
        try:
            resp = self.perform_request(url=url, type='post', data=data, files=files, with_progress=callback_dict)
        except PydioSdkDefaultException as e:
            logging.exception(e)
            if resp and resp.content:
                logging.info(resp.content)
            status_handler.update_node_status(path, 'PENDING')
            if e.message == '507':
                usage, total = self.quota_usage()
                raise PydioSdkQuotaException(path, local_stat['size'], usage, total)
            if e.message == '412':
                raise PydioSdkPermissionException('Cannot upload '+os.path.basename(path)+' in directory '+os.path.dirname(path))
            else:
                raise e
        except RequestException as ce:
            status_handler.update_node_status(path, 'PENDING')
            raise PydioSdkException("upload", str(path), 'RequestException: ' + str(ce))

        new = self.stat(path)
        if not new or not (new['size'] == local_stat['size']):
            status_handler.update_node_status(path, 'PENDING')
            beginning_filename = path.rfind('/')
            if beginning_filename > -1 and path[beginning_filename+1] == " ":
                raise PydioSdkException('upload', path, _("File beginning with a 'space' shouldn't be uploaded"))
            raise PydioSdkException('upload', path, _('File is incorrect after upload'))
        return True

    def upload(self, local, local_stat, path, callback_dict=None, max_upload_size=-1):
        """
        Upload a file to the server.
        :param local: file path
        :param local_stat: stat of the file
        :param path: target path on the server
        :param callback_dict: an dict that can be fed with progress data
        :param max_upload_size: a known or arbitrary upload max size. If the file file is bigger, it will be
        chunked into many POST requests
        :return: Server response
        """
        if not local_stat:
            raise PydioSdkException('upload', path, _('Local file to upload not found!'))
        existing_part = False
        if (self.upload_max_size - 4096) < local_stat['size']:
            self.has_disk_space_for_upload(path, local_stat['size'])
            existing_part = self.stat(path+'.dlpart', True)
        dirpath = os.path.dirname(path)
        if dirpath and dirpath != '/':
            folder = self.stat(dirpath)
            if not folder:
                self.mkdir(os.path.dirname(path))
        url = self.url + '/upload/put' + self.urlencode_normalized((self.remote_folder + os.path.dirname(path)))
        files = {
            'userfile_0': local
        }
        if existing_part:
            files['existing_dlpart'] = existing_part
        data = {
            'force_post': 'true',
            'xhr_uploader': 'true',
            'normalized_path': self.normalize(self.remote_folder + path),
            'urlencoded_filename': self.urlencode_normalized(os.path.basename(path))
        }
        try:
            self.perform_request(url=url, type='post', data=data, files=files, with_progress=callback_dict)
        except PydioSdkDefaultException as e:
            if e.message == '507':
                usage, total = self.quota_usage()
                raise PydioSdkQuotaException(path, local_stat['size'], usage, total)
            if e.message == '412':
                raise PydioSdkPermissionException('Cannot upload '+os.path.basename(path)+' in directory '+os.path.dirname(path))
            else:
                raise e
        except RequestException as ce:
            raise PydioSdkException("upload", str(path), 'RequestException: ' + str(ce.message))
        return True

    def stat_and_download(self, path, local, callback_dict=None):
        """
        Download the content of a server file to a local file.
        :param path: node path on the server
        :param local: local path on filesystem
        :param callback_dict: a dict() than can be updated by with progress data
        :return: Server response
        """
        orig = self.stat(path)
        if not orig:
            raise PydioSdkException('download', path, _('Original file was not found on server'), 1404)

        jwt = self.get_jwt()
        if jwt is not None:
            def cb(progress=0, delta=0, rate=0):
                if callback_dict:
                    callback_dict['bytes_sent'] = float(delta)
                    callback_dict['total_bytes_sent'] = float(progress)
                    callback_dict['total_size'] = float(orig['size'])
                    callback_dict['transfer_rate'] = 0
                    dispatcher.send(signal=TRANSFER_CALLBACK_SIGNAL,sender=self,change=callback_dict)
            resp = self.download_with_jwt(jwt, self.normalize(self.remote_folder + path), orig['size'], local, cb)
            return resp

        url = self.url + '/download' + self.urlencode_normalized((self.remote_folder + path))
        local_tmp = local + '.pydio_dl'
        headers = None
        write_mode = 'wb'
        dl = 0
        if not os.path.exists(os.path.dirname(local)):
            os.makedirs(os.path.dirname(local))
        elif os.path.exists(local_tmp):
            # A .pydio_dl already exists, maybe it's a chunk of the original?
            # Try to get an md5 of the corresponding chunk
            current_size = os.path.getsize(local_tmp)
            chunk_local_hash = hashfile(open(local_tmp, 'rb'), hashlib.md5())
            chunk_remote_stat = self.stat(path, True, partial_hash=[0, current_size])
            if chunk_remote_stat and chunk_local_hash == chunk_remote_stat['hash']:
                headers = {'range':'bytes=%i-%i' % (current_size, chunk_remote_stat['size'])}
                write_mode = 'a+'
                dl = current_size
                if callback_dict:
                    callback_dict['bytes_sent'] = float(current_size)
                    callback_dict['total_bytes_sent'] = float(current_size)
                    callback_dict['total_size'] = float(chunk_remote_stat['size'])
                    callback_dict['transfer_rate'] = 0
                    dispatcher.send(signal=TRANSFER_CALLBACK_SIGNAL, send=self, change=callback_dict)

            else:
                os.unlink(local_tmp)

        try:
            with open(local_tmp, write_mode) as fd:
                start = time.clock()
                r = self.perform_request(url=url, stream=True, headers=headers)
                total_length = r.headers.get('content-length')
                if total_length is None: # no content length header
                    fd.write(r.content)
                else:
                    previous_done = 0
                    for chunk in r.iter_content(1024 * 8):
                        if self.interrupt_tasks:
                            raise PydioSdkException("interrupt", path=path, detail=_('Task interrupted by user'))
                        dl += len(chunk)
                        fd.write(chunk)
                        done = int(50 * dl / int(total_length))
                        if done != previous_done:
                            transfer_rate = dl // (time.clock() - start)
                            logging.debug("\r[%s%s] %s bps" % ('=' * done, ' ' * (50 - done), transfer_rate))
                            dispatcher.send(signal=TRANSFER_RATE_SIGNAL, send=self, transfer_rate=transfer_rate)
                            if callback_dict:
                                callback_dict['bytes_sent'] = float(len(chunk))
                                callback_dict['total_bytes_sent'] = float(dl)
                                callback_dict['total_size'] = float(total_length)
                                callback_dict['transfer_rate'] = transfer_rate
                                dispatcher.send(signal=TRANSFER_CALLBACK_SIGNAL, send=self, change=callback_dict)

                        previous_done = done
            if not os.path.exists(local_tmp):
                raise PydioSdkException('download', local, _('File not found after download'))
            else:
                stat_result = os.stat(local_tmp)
                if not orig['size'] == stat_result.st_size:
                    os.unlink(local_tmp)
                    raise PydioSdkException('download', path, _('File is not correct after download'))
                else:
                    is_system_windows = platform.system().lower().startswith('win')
                    if is_system_windows and os.path.exists(local):
                        os.unlink(local)
                    os.rename(local_tmp, local)
            return True

        except PydioSdkException as pe:
            if pe.operation == 'interrupt':
                raise pe
            else:
                if os.path.exists(local_tmp):
                    os.unlink(local_tmp)
                raise pe

        except Exception as e:
            logging.exception(e)
            if os.path.exists(local_tmp):
                os.unlink(local_tmp)
            raise PydioSdkException('download', path, _('Error while downloading file: %s') % e.message)

    def download(self, path, local, callback_dict=None):
        """
        Download the content of a server file to a local file.
        :param path: node path on the server
        :param local: local path on filesystem
        :param callback_dict: a dict() than can be updated by with progress data
        :return: Server response
        """
        url = self.url + '/download' + self.urlencode_normalized((self.remote_folder + path))
        local_tmp = local + '.pydio_dl'
        headers = None
        write_mode = 'wb'
        dl = 0
        if not os.path.exists(os.path.dirname(local)):
            os.makedirs(os.path.dirname(local))
        elif os.path.exists(local_tmp):
            # A .pydio_dl already exists, maybe it's a chunk of the original?
            # Try to get an md5 of the corresponding chunk
            current_size = os.path.getsize(local_tmp)
            chunk_local_hash = hashfile(open(local_tmp, 'rb'), hashlib.md5())
            chunk_remote_stat = self.stat(path, True, partial_hash=[0, current_size])
            if chunk_remote_stat and chunk_local_hash == chunk_remote_stat['hash']:
                headers = {'range':'bytes=%i-%i' % (current_size, chunk_remote_stat['size'])}
                write_mode = 'a+'
                dl = current_size
                if callback_dict:
                    callback_dict['bytes_sent'] = float(current_size)
                    callback_dict['total_bytes_sent'] = float(current_size)
                    callback_dict['total_size'] = float(chunk_remote_stat['size'])
                    callback_dict['transfer_rate'] = 0
                    dispatcher.send(signal=TRANSFER_CALLBACK_SIGNAL, send=self, change=callback_dict)

            else:
                os.unlink(local_tmp)
        try:
            with open(local_tmp, write_mode) as fd:
                start = time.clock()
                r = self.perform_request(url=url, stream=True, headers=headers)
                total_length = r.headers.get('content-length')
                if total_length is None: # no content length header
                    fd.write(r.content)
                else:
                    previous_done = 0
                    for chunk in r.iter_content(1024 * 8):
                        if self.interrupt_tasks:
                            raise PydioSdkException("interrupt", path=path, detail=_('Task interrupted by user'))
                        dl += len(chunk)
                        fd.write(chunk)
                        done = int(50 * dl / int(total_length))
                        if done != previous_done:
                            transfer_rate = dl // (time.clock() - start)
                            logging.debug("\r[%s%s] %s bps" % ('=' * done, ' ' * (50 - done), transfer_rate))
                            dispatcher.send(signal=TRANSFER_RATE_SIGNAL, send=self, transfer_rate=transfer_rate)
                            if callback_dict:
                                callback_dict['bytes_sent'] = float(len(chunk))
                                callback_dict['total_bytes_sent'] = float(dl)
                                callback_dict['total_size'] = float(total_length)
                                callback_dict['transfer_rate'] = transfer_rate
                                dispatcher.send(signal=TRANSFER_CALLBACK_SIGNAL, send=self, change=callback_dict)

                        previous_done = done

            if not os.path.exists(local_tmp):
                raise PydioSdkException('download', local, _('File not found after download'))
            else:
                is_system_windows = platform.system().lower().startswith('win')
                if is_system_windows and os.path.exists(local):
                    os.unlink(local)
                os.rename(local_tmp, local)
            return True
        except PydioSdkException as pe:
            if pe.operation == 'interrupt':
                raise pe
            else:
                if os.path.exists(local_tmp):
                    os.unlink(local_tmp)
                raise pe
        except Exception as e:
            logging.exception(e)
            if os.path.exists(local_tmp):
                os.unlink(local_tmp)
            raise PydioSdkException('download', path, _('Error while downloading file: %s') % e.message)

    def list(self, dir=None, nodes=list(), options='al', recursive=False, max_depth=1, remote_order='', order_column='', order_direction='', max_nodes=0, call_back=None):
        url = self.url + '/ls' + self.urlencode_normalized(self.remote_folder)
        data = dict()
        if dir and dir is not '/':
            url += self.urlencode_normalized(dir)
        if nodes:
            data['nodes'] = nodes
        data['options'] = options
        if recursive:
            data['recursive'] = 'true'
        if max_depth > 1:
            data['max_depth'] = max_depth
        if max_nodes:
            data['max_nodes'] = max_nodes
        if remote_order:
            data['remote_order'] = remote_order
        if order_column:
            data['order_column'] = order_column
        if order_direction:
            data['order_direction'] = order_direction
        resp = self.perform_request(url=url, type='post', data=data)
        self.is_pydio_error_response(resp)
        queue = [ET.ElementTree(ET.fromstring(resp.content)).getroot()]
        snapshot = dict()
        while len(queue):
            tree = queue.pop(0)
            if tree.get('ajxp_mime') == 'ajxp_folder' or tree.get('ajxp_mime') == 'ajxp_browsable_archive':
                for subtree in tree.findall('tree'):
                    queue.append(subtree)
            path = self.normalize(unicode(tree.get('filename')))
            bytesize = tree.get('bytesize')
            dict_tree = dict(tree.items())
            if path:
                if call_back:
                    call_back(dict_tree)
                else:
                    snapshot[path] = bytesize
        return snapshot if not call_back else None

    def snapshot_from_changes(self, call_back=None):
        url = self.url + '/changes/0/?stream=true&flatten=true'
        if self.remote_folder:
            url += '&filter=' + self.urlencode_normalized(self.remote_folder)
        resp = self.perform_request(url=url, stream=True)
        files = dict()
        for line in resp.iter_lines(chunk_size=512):
            if not str(line).startswith('LAST_SEQ'):
                element = json.loads(line, strict=False)
                if call_back:
                    call_back(element)
                else:
                    path = element.pop('target')
                    bytesize = element['node']['bytesize']
                    if path != 'NULL':
                        files[path] = bytesize
        return files if not call_back else None

    def apply_check_hook(self, hook_name='', hook_arg='', file='/'):
        url = self.url + '/apply_check_hook/'+hook_name+'/'+str(hook_arg)+'/'
        resp = self.perform_request(url=url, type='post', data={'file': self.normalize(file).replace('\\', '/')})
        return resp

    def quota_usage(self):
        url = self.url + '/monitor_quota/'
        resp = self.perform_request(url=url, type='post')
        quota = json.loads(resp.text)
        return quota['USAGE'], quota['TOTAL']

    def has_disk_space_for_upload(self, path, file_size):
        resp = self.apply_check_hook(hook_name='before_create', hook_arg=file_size, file=path)
        if str(resp.text).count("type=\"ERROR\""):
            usage, total = self.quota_usage()
            raise PydioSdkQuotaException(path, file_size, usage, total)

    def is_pydio_error_response(self, resp):
        error = False
        message = 'Unknown error'
        try:
            root = ET.ElementTree(ET.fromstring(resp.content)).getroot()
            for e in root.getchildren():
                if e.tag == 'message' and 'type' in e.attrib:
                    if e.attrib['type'].lower() == 'error':
                        if len(e.text):
                            message = e.text
        except Exception as e:
            logging.exception(e)
            pass
        if resp.content.find('ERROR') > -1:
            logging.info(resp.url)
            logging.info("  Was this error properly handled? " + resp.content)
            error=True
        if error:
            raise PydioSdkDefaultException(message)

    def rsync_delta(self, path, signature, delta_path):
        url = self.url + ('/filehasher_delta' + self.urlencode_normalized(self.remote_folder + path.replace("\\", "/")))
        resp = self.perform_request(url=url, type='post', files={'userfile_0': signature}, stream=True,
                                    with_progress=False)
        fd = open(delta_path, 'wb')
        for chunk in resp.iter_content(8192):
            fd.write(chunk)
        fd.close()

    def rsync_signature(self, path, signature):
        url = self.url + ('/filehasher_signature'+ self.urlencode_normalized(self.remote_folder + path.replace("\\", "/")))
        resp = self.perform_request(url=url, type='post', stream=True, with_progress=False)
        fd = open(signature, 'wb')
        for chunk in resp.iter_content(8192):
            fd.write(chunk)
        fd.close()

    def rsync_patch(self, path, delta_path):
        url = self.url + ('/filehasher_patch'+ self.urlencode_normalized(self.remote_folder + path.replace("\\", "/")))
        resp = self.perform_request(url=url, type='post', files={'userfile_0': delta_path}, with_progress=False)
        self.is_pydio_error_response(resp)

    def is_rsync_supported(self):
        return self.rsync_supported

    def upload_file_with_progress(self, url, fields, files, stream, with_progress, max_size=0, auth=None):
        """
        Upload a file with progress, file chunking if necessary, and stream content directly from file.
        :param url: url to post
        :param fields: dict() query parameters
        :param files: dict() {'fieldname' : '/path/to/file'}
        :param stream: whether to get response as stream or not
        :param with_progress: dict() updatable dict with progress data
        :param max_size: upload max size
        :return: response of the last requests if there were many of them
        """
        if with_progress:
            def cb(size=0, progress=0, delta=0, rate=0):
                with_progress['total_size'] = size
                with_progress['bytes_sent'] = delta
                with_progress['total_bytes_sent'] = progress
                dispatcher.send(signal=TRANSFER_CALLBACK_SIGNAL, sender=self, change=with_progress)
        else:
            def cb(size=0, progress=0, delta=0, rate=0):
                logging.debug('Current transfer rate ' + str(rate))

        def parse_upload_rep(http_response):
            #logging.info(http_response.text)
            if http_response.headers.get('content-type') != 'application/octet-stream':
                if unicode(http_response.text).count('message type="ERROR"'):

                    if unicode(http_response.text).lower().count("(507)"):
                        raise PydioSdkDefaultException('507')

                    if unicode(http_response.text).lower().count("(412)"):
                        raise PydioSdkDefaultException('412')

                    import re
                    # Remove XML tags
                    text = re.sub('<[^<]+>', '', unicode(http_response.text))
                    raise PydioSdkDefaultException(text)

                if unicode(http_response.text).lower().count("(507)"):
                    raise PydioSdkDefaultException('507')

                if unicode(http_response.text).lower().count("(412)"):
                    raise PydioSdkDefaultException('412')

                if unicode(http_response.text).lower().count("(410)") or unicode(http_response.text).lower().count("(411)"):
                    raise PydioSdkDefaultException(unicode(http_response.text))

        try:
            filesize = os.stat(files['userfile_0']).st_size
        except OSError as e:
            if e.errno == 2:
                raise PydioSdkException('upload', files['userfile_0'], _('Local file to upload not found!'))
            else:
                raise e

        jwt = self.get_jwt()
        if jwt is not None:
            remote = fields['normalized_path']
            resp = self.upload_with_jwt(jwt, files['userfile_0'], self.ws_id + '/' + remote.strip('/'), cb)
            return resp

        if max_size:
            # Reduce max size to leave some room for data header
            max_size -= 4096

        existing_pieces_number = 0

        if max_size and filesize > max_size:
            fields['partial_upload'] = 'true'
            fields['partial_target_bytesize'] = str(filesize)
            # Check if there is already a .dlpart on the server.
            # If it's the case, maybe it's already the beginning of this?
            if 'existing_dlpart' in files:
                existing_dlpart = files['existing_dlpart']
                existing_dlpart_size = existing_dlpart['size']
                if filesize > existing_dlpart_size and \
                        file_start_hash_match(files['userfile_0'], existing_dlpart_size, existing_dlpart['hash']):
                    logging.info('Found the beginning of this file on the other file, skipping the first pieces')
                    existing_pieces_number = existing_dlpart_size / max_size
                    cb(filesize, existing_dlpart_size, existing_dlpart_size, 0)

        if not existing_pieces_number:

            # try:
            #     import http.client as http_client
            # except ImportError:
            #     # Python 2
            #     import httplib as http_client
            # http_client.HTTPConnection.debuglevel = 1
            #
            # logging.getLogger().setLevel(logging.DEBUG)
            # requests_log = logging.getLogger("requests.packages.urllib3")
            # requests_log.setLevel(logging.DEBUG)
            # requests_log.propagate = True

            (header_body, close_body, content_type) = encode_multiparts(fields)
            body = BytesIOWithFile(header_body, close_body, files['userfile_0'], callback=cb, chunk_size=max_size,
                                   file_part=0, signal_sender=self)
            #logging.info(url)
            resp = requests.post(
                url,
                data=body,
                headers={'Content-Type': content_type},
                stream=True,
                timeout=self.timeout,
                verify=self.verify_ssl,
                auth=auth,
                proxies=self.proxies
            )

            existing_pieces_number = 1
            parse_upload_rep(resp)
            if resp.status_code == 401:
                return resp

        if max_size and filesize > max_size:
            fields['appendto_urlencoded_part'] = fields['urlencoded_filename']
            #del fields['urlencoded_filename']  # doesn't make sense, for some reason it was added at some point...
            (header_body, close_body, content_type) = encode_multiparts(fields)
            for i in range(existing_pieces_number, int(math.ceil(filesize / max_size)) + 1):

                if self.interrupt_tasks:
                    raise PydioSdkException("upload", path=os.path.basename(files['userfile_0']), detail=_('Task interrupted by user'))

                before = time.time()
                body = BytesIOWithFile(header_body, close_body, files['userfile_0'],
                                       callback=cb, chunk_size=max_size, file_part=i, signal_sender=self)
                resp = requests.post(
                    url,
                    data=body,
                    headers={'Content-Type': content_type},
                    stream=True,
                    verify=self.verify_ssl,
                    auth=auth,
                    proxies=self.proxies
                )
                parse_upload_rep(resp)
                if resp.status_code == 401:
                    return resp

                duration = time.time() - before
                logging.info('Uploaded '+str(max_size)+' bytes of data in about %'+str(duration)+' s')

        return resp

    def get_jwt(self):

        if self.jwtNotSupported:
            return None

        if self.jwt is not None and not self.jwt_needs_refresh():
            return self.jwt

        try:
            resp = self.perform_request(url=self.base_url+'pydio/jwt?client_time=' + str(int(time.time())),type='get')
            if resp.status_code == 404 or 'Could not find action' in resp.content:
                self.jwtNotSupported = True
                return None
            parsed = json.loads(resp.content)
            if parsed and parsed['jwt']:
                self.jwt = parsed['jwt']
                self.jwtExpiration = int(parsed['expirationTime'])
                return self.jwt
        except Exception as e:
            logging.error('JWT not available')
            pass
        return None

    def jwt_needs_refresh(self):
        return self.jwtExpiration - time.time() < 60 * 5

    def upload_with_jwt(self, jwt, local_file, remote_path, cb):
        MB = 1024 ** 2
        config = TransferConfig(multipart_threshold=20 * MB, io_chunksize= 10 * MB, max_concurrency=5)
        client = boto3.client(
            service_name='s3',
            endpoint_url=self.base_url.replace('/api/', ''),
            verify=self.verify_ssl,
            aws_access_key_id=jwt,
            aws_secret_access_key='gatewaysecret',
        )

        stat = os.stat(local_file)
        size = stat.st_size
        total = [0]

        def s3cb(transferred):
            total[0] += transferred
            cb(size=size, progress=total[0], delta=transferred)

        bucket = 'io'
        key = remote_path
        try:
            client.upload_file(local_file, bucket, key, Callback=s3cb, Config=config)
        except Exception as e:
            raise PydioSdkDefaultException(e.message)

        class MockResponse:
            def __init__(self):
                self.status_code = 200
        return MockResponse()

    def download_with_jwt(self, jwt, remote_path, remote_size, local_file, cb):
        local_tmp = local_file + '.pydio_dl'
        client = boto3.client(
            service_name='s3',
            endpoint_url=self.base_url.replace('/api/', ''),
            verify=self.verify_ssl,
            aws_access_key_id=jwt,
            aws_secret_access_key='gatewaysecret',
        )

        total = [0]

        def s3cb(transferred):
            total[0] += transferred
            cb(progress=total[0], delta=transferred)

        bucket = 'io'
        key = self.ws_id + '/' + remote_path.strip('/')
        try:
            client.download_file(Filename=local_tmp, Bucket=bucket, Key=key)
        except Exception as e:
            raise PydioSdkDefaultException(e.message)

        if not os.path.exists(local_tmp):
            raise PydioSdkException('download', local_file, _('File not found after download'))
        else:
            stat_result = os.stat(local_tmp)
            if not remote_size == stat_result.st_size:
                os.unlink(local_tmp)
                raise PydioSdkException('download', remote_path, _('File is not correct after download'))
            else:
                is_system_windows = platform.system().lower().startswith('win')
                if is_system_windows and os.path.exists(local_file):
                    os.unlink(local_file)
                os.rename(local_tmp, local_file)
        return True

    def check_share_link(self, file_name):
        """ Check if a share link exists for a given item (filename)

        :param file_name: the item name
        :return: response string from the server, it'll return the a link if share link already exists for the given item
        """
        data = dict()
        resp = requests.post(
                    url=self.url + "/load_shared_element_data" + self.urlencode_normalized(file_name),
                    data=data,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    auth=self.auth,
                    proxies=self.proxies)

        return resp.content

    def share(self, ws_label, ws_description, password, expiration, downloads, can_read, can_download, paths,
                    link_handler, can_write):
        """ Send the share request for an item (file or folder) to the server and gets the response from the server

        :param ws_label: alias of the workspace/ workspace id
        :param ws_description: The description of the workspace
        :param password: if the share has to be protected by password, should be mentioned
        :param expiration: The share link expires after how many days
        :param downloads: Number of downloads allowed on the shared link
        :param can_read: boolean value - person with link can read?
        :param can_download: boolean value - person with link can download?
        :param paths: the relative path of the file to be shared
        :param link_handler: Can create a custom link by specifying the custom name in this field
        :param can_write: boolean value - person with link can modify?
        :return: response string from the server, it'll return the a share link if all the parameters are correct
        """
        data = dict()
        data["sub_action"] = "create_minisite"
        data["guest_user_pass"] = password
        data["create_guest_user"] = "true"
        data["share_type"] = "on"
        data["expiration"] = expiration
        data["downloadlimit"] = downloads
        data["repo_description"] = ws_description
        data["repo_label"] = ws_label
        data["custom_handle"] = link_handler

        if can_download == "true":
            data["simple_right_download"] = "on"
        if can_read == "true":
            data["simple_right_read"] = "on"
        else:
            data["minisite_layout"] = "ajxp_unique_dl"
        if can_write == "true":
            data["simple_right_write"] = "on"
        #logging.info("URL : " + self.url + '/share/public' + self.urlencode_normalized(paths) + "\nDATA " + str(data))
        resp = requests.post(
            url=self.url + '/share/public' + self.urlencode_normalized(paths),
            data=data,
            timeout=self.timeout,
            verify=self.verify_ssl,
            auth=self.auth,
            proxies=self.proxies)
        return resp.content

    def copy(self, files_to_copy, dest_folder):
        """ Copy a file or a list of files to dest_folder
            :param files_to_copy: full path origin file or list of full path origin files
            :param dest_folder: full path destination file or folder
        """
        url = self.url + '/copy/'
        data = dict()
        data["dest"] = dest_folder
        if isinstance(files_to_copy, str) or isinstance(files_to_copy, unicode):
            data["nodes[]"] = files_to_copy
        elif isinstance(files_to_copy, list):
            i = 0
            for filepath in files_to_copy:
                data["node[" + str(i) + "]"] = filepath
                i += 1
        else:
            logging.info("Couldn't understand input files_to_copy " + str(files_to_copy))
        resp = self.perform_request(url, type='post', data=data)
        #logging.info(resp.content)
        self.is_pydio_error_response(resp)
        return resp.content


    def unshare(self, path):
        """ Sends un-share request for the specified item and returns the server response

        :param path: The path of the item to be shared
        :return: On success returns empty string, when the response status is not 200 returns the corresponding error message
        """
        data = dict()
        resp = requests.post(
            url=self.url+'/unshare' + self.urlencode_normalized(path),
            data=data,
            timeout=self.timeout,
            verify=self.verify_ssl,
            auth=self.auth,
            proxies=self.proxies)

        return resp.content

    def install(self, json_form_data):

        session_access = self.base_url.replace('/api/', '/').rstrip('/')
        print "Installing server " + session_access
        s = requests.Session()
        # Make sure we go through the bootSequence to create RootGroup
        s.get(
            url=session_access,
            timeout=self.timeout,
            verify=self.verify_ssl,
            proxies=self.proxies,
            headers={'Accept': 'text/html'}
        )
        s.get(
            url=session_access + '/?ignore_tests=true',
            timeout=self.timeout,
            verify=self.verify_ssl,
            proxies=self.proxies,
            headers={'Accept': 'text/html'}
        )

        # Cannot use REST, Get Token First
        resp1 = s.get(
            url=session_access + '/?get_action=get_boot_conf',
            timeout=self.timeout,
            verify=self.verify_ssl,
            proxies=self.proxies
        )
        resp_json = json.loads(resp1.content)
        token = resp_json['SECURE_TOKEN']

        print "Retrieved Secure Token : " + token

        # Now Apply Installer Form
        json_form_data['db_type'] = json.dumps(json_form_data['db_type'])
        json_form_data['MAILER_ENABLE'] = json.dumps(json_form_data['MAILER_ENABLE'])
        import time
        json_form_data['APPLICATION_WELCOME'] += ' - ' + time.strftime("%Y-%m-%d %H:%M")

        resp = s.post(
            url= session_access + '/?secure_token='+token+'&get_action=apply_installer_form',
            data=json_form_data,
            timeout=self.timeout,
            verify=self.verify_ssl,
            proxies=self.proxies
        )

        print "Submitted install form with response : " + resp.content
        return resp.content

    def get_user_rep(self):
        #TODO: finish me
        url = self.base_url + "pydio/state/user/repositories?format=json"
        resp = None
        try:
            resp = self.perform_request(url)
            repo_data = json.loads(resp.content)
            for r in repo_data['repositories']['repo']:
                if r['@repositorySlug'] == self.ws_id:
                    return r['@id']
        except Exception as e:
            logging.exception(e)
        logging.info("Couldn't find repository id (" + self.ws_id + " @ " + url + ")")
        return None

    def websocket_connect(self, last_seq, job_id=None):
        """
        Instead of polling this blocks until <node_diff>(s) are received
        This is dirty hacking going on here, we'll have to design a cleaner API
        Authenticate on the websocket channel and fetch the list of watchable repos would be ideal
        :param last_seq:
        :return:
        """
        # fetch repo_id
        if self.remote_repo_id is None:
            self.remote_repo_id = self.get_user_rep()
        host = None
        port = None
        ws_server = "ws://"
        try:
            #logging.info("Server data " + str(self.websocket_server_data))
            if "BOOSTER_MAIN_HOST" in self.websocket_server_data:
                host = self.websocket_server_data["BOOSTER_MAIN_HOST"]
            if "BOOSTER_MAIN_PORT" in self.websocket_server_data:
                port = self.websocket_server_data["BOOSTER_MAIN_PORT"]
            if "BOOSTER_WS_ADVANCED" in self.websocket_server_data:
                booster_ws_advanced = self.websocket_server_data['BOOSTER_WS_ADVANCED']
                if 'booster_ws_advanced' in booster_ws_advanced and\
                        booster_ws_advanced['booster_ws_advanced'] == 'custom' and 'WS_HOST' in booster_ws_advanced:
                    host = booster_ws_advanced['WS_HOST']
                    if "BOOSTER_MAIN_PORT" in booster_ws_advanced:
                        port = booster_ws_advanced["BOOSTER_MAIN_PORT"]
                    if "WS_PORT" in booster_ws_advanced:
                        port = booster_ws_advanced["WS_PORT"]
            if "WS_ACTIVE" in self.websocket_server_data:
                if self.websocket_server_data['WS_ACTIVE'] == 'true':
                    if 'WS_SECURE' in self.websocket_server_data:
                        if self.websocket_server_data['WS_SECURE'] == 'true':
                            ws_server = "wss://"
                    if 'BOOSTER_MAIN_SECURE' in self.websocket_server_data:
                        if self.websocket_server_data['BOOSTER_MAIN_SECURE'] == 'true':
                            ws_server = "wss://"
                    ws_server += host + ":" + port + "/" + self.websocket_server_data["WS_PATH"]
                    self.waiter = Waiter(ws_server, self.remote_repo_id, self.get_tokens(), self.ws_id, self.verify_ssl)
                    self.waiter.start()
                else:
                    return False
            else:
                #logging.info('Websocket server marked inactive.')
                return False
        except Exception as e:
            if hasattr(e, "errno") and e.errno == 61:
                self.failedWebSocketConnection += 1
                logging.info("Failed to connect to websockets")
                return False
            else:
                logging.exception(e)
                return False
        return True

    def websocket_disconnect(self):
        self.waiter.wait = False
        self.waiter.ws.close()

class Waiter(threading.Thread):
    def __init__(self, ws_reg_path, repo_id, tokens, job_id, verify_ssl=True):
        threading.Thread.__init__(self)
        if not verify_ssl:
            self.ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
        else:
            self.ws = websocket.WebSocket()
        self.ws_reg_path = ws_reg_path
        self.wait = True
        self.should_fetch_changes = False
        self.repo_id = repo_id
        self.job_id = job_id
        self.tokens = tokens
        self.failedWebSocketConnection = 0
        self.nextReconnect = 0

    def register(self):
        #logging.info("[ws] Register websockets on workspace " + self.job_id)
        try:
            nonce = sha1(str(random.random())).hexdigest()
            uri = "/api/pydio/ws_authenticate"  # TODO: ideally this should be server dependent
            msg = uri + ':' + nonce + ':' + self.tokens['p']
            the_hash = hmac.new(str(self.tokens['t']), str(msg), sha256)
            auth_hash = nonce + ':' + the_hash.hexdigest()
            mess = "auth_hash=" + auth_hash + '&auth_token=' + self.tokens['t']
            #logging.info("Connecting to " + self.ws_reg_path + "?" + mess)
            self.ws.connect(self.ws_reg_path + "?" + mess)
            self.ws.send("register:" + self.repo_id)
        except websocket.WebSocketConnectionClosedException:
            self.failedWebSocketConnection += 1
            logging.info("[ws] Websocket server (" + self.ws_reg_path + ") not responding for " + self.job_id + ".")
            self.should_fetch_changes = True  # Terminate from caller
            return
        except Exception as e:
            self.failedWebSocketConnection += 1
            logging.exception(e)
            logging.info("[SSL]" + ssl.OPENSSL_VERSION)
            logging.info("[ws] Websocket registration failed with URL: " + self.ws_reg_path + "?" + mess)
            logging.info("[ws] payload was: " + "register:" + self.repo_id)
            self.should_fetch_changes = True  # Terminate from caller
            return

    def wait_for_changes(self):
        i = 0  # current number of connection attempts
        if self.failedWebSocketConnection > 5:
            if self.nextReconnect == 0:
                # Will wait for 300s, then try to reconnect
                logging.info("[ws] Disabling websockets, too many failures. " + self.job_id)
                self.nextReconnect = time.time() + 300
            elif time.time() > self.nextReconnect:
                self.nextReconnect = 0
                self.failedWebSocketConnection -= 2
            return
        while self.wait and i < 2:
            try:
                logging.info("[ws] Waiting for nodes_diff on workspace " + self.job_id)
                # TODO FIND A WAY TO KILL IT
                res = self.ws.recv()
                logging.info("[ws] message received %r [...]", res[:142])
                #if res.find("nodes_diff") > -1 or res.find('reload') > -1: # parse messages ?
                self.should_fetch_changes = True
                i = 0
            except websocket.WebSocketConnectionClosedException:
                i += 1
                self.failedWebSocketConnection += 1
                self.register()  # spaghetti, reconnect if for some reason the connection was closed
                time.sleep(.5)
            except Exception as e:
                i += 1
                self.failedWebSocketConnection += 1
                logging.info("[ws] Failed to receive websocket data on workspace " + self.job_id)
                logging.exception(e)
                self.should_fetch_changes = True
                self.register()  # spaghetti, reconnect if for some reason the connection was closed
                time.sleep(.5)

    def run(self):
        self.register()
        while self.wait:
            self.wait_for_changes()
            time.sleep(1)
    # end thread run

    def stop(self):
        self.wait = False
        if self.ws.connected:
            self.ws.send_close(websocket.STATUS_NORMAL, reason="User disconnect")
        self.ws.close()
        self.ws.abort()
# end of Waiter
