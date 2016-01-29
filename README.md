pydio-sdk-python
================

Python SDK to communicate with Pydio backend.

Installation instructions
=========================

    git submodule add git@git@gtihub.com:pydio/pydio-sdk-python pydiosdkpython
    git submodule init
    git submodule update
    virtualenv pydio --python=python3
    source pydio/bin/activate
    pip -r pydio/requirements.txt

Example usage
=============
    python
         from pydiosdkpython.remote import PydioSdk
         import json
         PASSWORD = "pydiopassword"
         job = "server.my-files"
         configs_path = "path/to/configs.json" # PydioSync > About > Open Pydio Logs
         with open(configs_path) as conf_handler:
             conf = json.load(conf_handler)
         sdk = PydioSdk(conf[job]['server'], conf[job]['workspace'], conf[job]['remote_folder'], '', auth=(conf[job]['user'], PASSWORD))
         try: 
           print(sdk.list())
         except requests.exceptions.SSLError:
           sdk = PydioSdk(conf[job]['server'], conf[job]['workspace'], conf[job]['remote_folder'], '', auth=(conf[job]['user'], PASSWORD), skip_ssl_verify=True)
           print(sdk.list())
