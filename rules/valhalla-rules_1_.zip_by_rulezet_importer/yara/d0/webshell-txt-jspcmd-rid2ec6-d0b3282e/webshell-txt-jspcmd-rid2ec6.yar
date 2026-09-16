rule Webshell_Txt_jspcmd_RID2EC6 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file jspcmd.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:28:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
      $s4 = "out.print(\"Hi,Man 2015\");" fullword ascii
   condition: 
      filesize < 1KB and 1 of them
}