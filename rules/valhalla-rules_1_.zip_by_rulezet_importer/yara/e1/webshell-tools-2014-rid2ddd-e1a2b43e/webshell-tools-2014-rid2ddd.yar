rule Webshell_Tools_2014_RID2DDD : CHINA DEMO T1007 T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file 2014.jsp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:50:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1007, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
      $s4 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
      $s5 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii
   condition: 
      filesize < 715KB and all of them
}