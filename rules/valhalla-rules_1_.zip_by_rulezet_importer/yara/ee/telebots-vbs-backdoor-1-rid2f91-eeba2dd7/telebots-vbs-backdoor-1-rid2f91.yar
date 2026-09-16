rule TeleBots_VBS_Backdoor_1_RID2F91 : APT DEMO FILE G0034 SCRIPT {
   meta:
      description = "Detects TeleBots malware - VBS Backdoor"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/"
      date = "2016-12-14 12:02:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "eb31a918ccc1643d069cf08b7958e2760e8551ba3b88ea9e5d496e07437273b2"
      tags = "APT, DEMO, FILE, G0034, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cmd = \"cmd.exe /c \" + arg + \" >\" + outfile +\" 2>&1\"" fullword ascii
      $s2 = "GetTemp = \"c:\\WINDOWS\\addins\"" fullword ascii
      $s3 = "elseif (arg0 = \"-dump\") Then" fullword ascii
      $s4 = "decode = \"certutil -decode \" + source + \" \" + dest  " fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x6553 and filesize < 8KB and 1 of them ) or ( all of them )
}