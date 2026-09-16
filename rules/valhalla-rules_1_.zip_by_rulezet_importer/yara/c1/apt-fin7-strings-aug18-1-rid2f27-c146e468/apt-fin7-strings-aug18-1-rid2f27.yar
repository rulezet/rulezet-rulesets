rule APT_FIN7_Strings_Aug18_1_RID2F27 : APT DEMO G0046 RUSSIA {
   meta:
      description = "Detects strings from FIN7 report in August 2018"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01 11:45:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b6354e46af0d69b6998dbed2fceae60a3b207584e08179748e65511d45849b00"
      tags = "APT, DEMO, G0046, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "&&call %a01%%a02% /e:jscript" ascii
      $s2 = "wscript.exe //b /e:jscript %TEMP%" ascii
      $s3 = " w=wsc@ript /b " ascii
      $s4 = "@echo %w:@=%|cmd" ascii
      $s5 = " & wscript //b /e:jscript" 
   condition: 
      1 of them
}