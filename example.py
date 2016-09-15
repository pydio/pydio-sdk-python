from remote import PydioSdk

sdk = PydioSdk(u"http://localhost", "my-files", u"/", '', auth=('user', 'password'))
print(sdk.list())
