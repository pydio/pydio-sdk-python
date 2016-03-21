pydio-sdk-python
================

Python SDK to communicate with Pydio backend. 

We currently use the Python 2 branch.

(The master branch in Python 3 should be up to date and documented. The Python 2 branch exists for backward compatibility and transition.)

Installation instructions
=========================

    git submodule add git@github.com:pydio/pydio-sdk-python pydiosdkpython
    git submodule init
    git submodule update
    virtualenv pydio --python=python3
    source pydio/bin/activate
    pip -r pydio/requirements.txt

Example usage
=============
## List files in *My Files*

```python
from pydiosdkpython.remote import PydioSdk

sdk = PydioSdk("http(s)://localhost/pydio", "my-files", "/", '', auth=('user', 'password'))
print(sdk.list())
```
