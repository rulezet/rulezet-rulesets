rule Webshell_asp_proxy_RID2E8B : DEMO T1090 T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file proxy.asp"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:19:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1090, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "'response.write \"<br/>  -value:\" & request.querystring(key)(j)" fullword ascii
      $s2 = "q = q & \"&\" & key & \"=\" & request.querystring(key)(j)" fullword ascii
      $s3 = "for each i in Split(http.getAllResponseHeaders, vbLf)" fullword ascii
      $s4 = "'urlquery = mid(urltemp, instr(urltemp, \"?\") + 1)" fullword ascii
      $s5 = "s = urlscheme & urlhost & urlport & urlpath" fullword ascii
      $s6 = "Set http = Server.CreateObject(\"Microsoft.XMLHTTP\")" fullword ascii
   condition: 
      filesize < 50KB and all of them
}