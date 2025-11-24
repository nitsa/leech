L.E.E.C.H is a Python tool used for data exfiltration by exploiting publicly exposed web server logs.

It was presented in DeepSec 2025 https://deepsec.net/speaker.html#PSLOT773.

It has two operation modes. First operation is file upload and second is file download. Uploaded file is compressed and encrypted, then split into chunks and Base64 encoded as part of the URI. 

A generated file ID can later be used to download the file. The tool has a basic configuration like random sleep duration between requests, chunk size, minimal URI pattern signature and encryption key. 

Different log types can easily be supported with minimal code changes.

Please change the default encryption keys before using it.

web_service.py is an example of a local web service which exposed locally the file access.log

leech.py is the actual tool.

Note that tool should be used without breaking the law and in order to conduct legal activities.

