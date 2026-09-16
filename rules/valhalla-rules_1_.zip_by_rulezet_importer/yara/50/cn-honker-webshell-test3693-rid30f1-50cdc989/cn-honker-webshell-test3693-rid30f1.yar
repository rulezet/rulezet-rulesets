rule CN_Honker_Webshell_test3693_RID30F1 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file test3693.war"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:01:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Process p=Runtime.getRuntime().exec(\"cmd /c \"+strCmd);" fullword ascii
      $s2 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - " ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 50KB and all of them
}