""" Malicious packets with different attacks for testing
"""

sql_injections = [
    r"""GET /WebGoat/attack?Screen=308&menu=1100&account_name=Erwin%27+OR+%271%27%3D%271&SUBMIT=Go! HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:42.0) Gecko/20100101 Firefox/42.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Referer: http://localhost:8080/WebGoat/start.mvc
Cookie: JSESSIONID=CE60351F53A5FA1999D9021FBB0F56E1
Connection: keep-alive""",
    r"""GET /WebGoat/attack?Screen=312&menu=1200&Username=user&Password=%27+or+%271%27+%3D+%271&SUBMIT=Login HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:42.0) Gecko/20100101 Firefox/42.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Referer: http://localhost:8080/WebGoat/start.mvc
Cookie: JSESSIONID=CE60351F53A5FA1999D9021FBB0F56E1
Connection: keep-alive"""
]

xss = [r"""GET /WebGoat/attack?Screen=268&menu=900&title=Test&message=%3Cscript%3Ealert(%22attack%22)%3C%2Fscript%3E&SUBMIT=Submit HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:42.0) Gecko/20100101 Firefox/42.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Referer: http://localhost:8080/WebGoat/start.mvc
Cookie: JSESSIONID=CE60351F53A5FA1999D9021FBB0F56E1
Connection: keep-alive""",
       r"""GET /WebGoat/attack?Screen=279&menu=900&QTY1=1&QTY2=1&QTY3=1&QTY4=1&field2=4128+3214+0002+1999&field1=%3CSCRIPT%3Ealert(%27bang!%27)%3B%3C%2FSCRIPT%3E111&SUBMIT=Purchase HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:42.0) Gecko/20100101 Firefox/42.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Referer: http://localhost:8080/WebGoat/start.mvc
Cookie: JSESSIONID=CE60351F53A5FA1999D9021FBB0F56E1
Connection: keep-alive"""
       ]