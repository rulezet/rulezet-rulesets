rule Webshell_InjectionParameters_RID325D : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file InjectionParameters.vb"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 14:02:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Public Shared ReadOnly Empty As New InjectionParameters(-1, \"\")" fullword ascii
      $s1 = "Public Class InjectionParameters" fullword ascii
   condition: 
      filesize < 13KB and all of them
}