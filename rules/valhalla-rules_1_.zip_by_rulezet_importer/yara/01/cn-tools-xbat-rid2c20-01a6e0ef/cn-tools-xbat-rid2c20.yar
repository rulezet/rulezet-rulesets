rule CN_Tools_xbat_RID2C20 : APT CHINA DEMO FILE SCRIPT {
   meta:
      description = "Chinese Hacktool Set - file xbat.vbs"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:35:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, FILE, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "ws.run \"srss.bat /start\",0 " fullword ascii
      $s1 = "Set ws = Wscript.CreateObject(\"Wscript.Shell\")" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x6553 and filesize < 0KB and all of them
}