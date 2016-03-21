pydio-sdk-python
================

Python 2 SDK to communicate with Pydio backend.

Installation instructions
=========================

Python 2
--------

    git submodule add -b python2 https://github.com/pydio/pydio-sdk-python pydiosdkpython
    git submodule init
    git submodule update
    virtualenv pydio --python=python2
    source pydio/bin/activate
    pip -r pydio/requirements.txt

Python 3
--------

    git submodule add https://github.com/pydio/pydio-sdk-python pydiosdkpython
    git submodule init
    git submodule update
    virtualenv pydio --python=python3
    source pydio/bin/activate
    pip -r pydio/requirements.txt

Example usage
=============

List the file in *My Files*
---------------------------

```python
from pydiosdkpython.remote import PydioSdk
import json

sdk = PydioSdk("http(s)://localhost/pydio", "my-files", "/", '', auth=('user', 'password'))
print(sdk.list())
```

