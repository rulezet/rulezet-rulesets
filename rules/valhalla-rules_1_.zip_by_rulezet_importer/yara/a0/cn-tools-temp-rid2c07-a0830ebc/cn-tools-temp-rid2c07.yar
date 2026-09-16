rule CN_Tools_Temp_RID2C07 : APT CHINA DEMO FILE {
   meta:
      description = "Chinese Hacktool Set - file Temp.war"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:31:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "META-INF/context.xml<?xml version=\"1.0\" encoding=\"UTF-8\"?>" fullword ascii
      $s1 = "browser.jsp" fullword ascii
      $s3 = "cmd.jsp" fullword ascii
      $s4 = "index.jsp" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 203KB and all of them
}