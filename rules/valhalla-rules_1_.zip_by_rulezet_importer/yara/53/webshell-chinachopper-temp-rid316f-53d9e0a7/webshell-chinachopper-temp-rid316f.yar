rule Webshell_ChinaChopper_temp_RID316F : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file temp.asp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:22:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "o.run \"ff\",Server,Response,Request,Application,Session,Error" fullword ascii
      $s1 = "Set o = Server.CreateObject(\"ScriptControl\")" fullword ascii
      $s2 = "o.language = \"vbscript\"" fullword ascii
      $s3 = "o.addcode(Request(\"SC\"))" fullword ascii
   condition: 
      filesize < 1KB and all of them
}