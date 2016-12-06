# -*- coding: utf-8 -*-
#
# Copyright 2007-2016 Charles du Jeu - Abstrium SAS <team (at) pyd.io>
#  This file is part of Pydio.
#
#  Pydio is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Pydio is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Affero General Public License for more details.
#
#  You should have received a copy of the GNU Affero General Public License
#  along with Pydio.  If not, see <http://www.gnu.org/licenses/>.
#
#  The latest code can be found at <http://pyd.io/>.
#

from remote import PydioSdk
import xml.etree.ElementTree as ET
from configs.commons import inner_debug


class SettingsSdk(PydioSdk):

    def __init__(self, server_def):
        PydioSdk.__init__(self, server_def['host'], 'ajxp_conf', unicode(''), '', (server_def['user'], server_def['pass']))
        self.stick_to_basic = True

    def create_repo(self, repo_def):
        import json
        json_data = json.dumps(repo_def)
        resp = self.perform_request(self.url+'/create_repository/'+json_data, 'post')
        inner_debug(resp.content)
        queue = [ET.ElementTree(ET.fromstring(resp.content)).getroot()]
        tree = queue.pop(0)
        message = tree.findall('message').pop(0)
        if message.get('type') == 'SUCCESS':
            reload_node = tree.findall('reload_instruction').pop(0)
            new_repo_id = reload_node.get('file')
            if 'META_SOURCES' in repo_def['DRIVER_OPTIONS']:
                self.add_meta_sources(new_repo_id, {'add': repo_def['DRIVER_OPTIONS']['META_SOURCES']})
            return new_repo_id
        else:
            raise Exception('Error while creating workspace')

    def delete_repo(self, repo_id):
        resp = self.perform_request(self.url+'/delete/repository/'+repo_id)
        inner_debug(resp.content)

    def add_meta_sources(self, repo_id, metasources):
        import json
        post = {'repository_id': repo_id, 'bulk_data': json.dumps(metasources)}
        resp = self.perform_request(self.url + '/edit/meta_source_edit', 'post', post)
        inner_debug(resp)