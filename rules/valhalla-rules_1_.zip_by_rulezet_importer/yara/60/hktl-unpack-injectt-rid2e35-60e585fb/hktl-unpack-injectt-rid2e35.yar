rule HKTL_Unpack_Injectt_RID2E35 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file Injectt.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:04:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "%s -Run                              -->To Install And Run The Service" 
      $s3 = "%s -Uninstall                        -->To Uninstall The Service" 
      $s4 = "(STANDARD_RIGHTS_REQUIRED |SC_MANAGER_CONNECT |SC_MANAGER_CREATE_SERVICE |SC_MAN" 
   condition: 
      all of them
}