rule TeleBots_VBS_Backdoor_2_RID2F92 : APT DEMO FILE G0034 SCRIPT {
   meta:
      description = "Detects TeleBots malware - VBS Backdoor"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/"
      date = "2016-12-14 12:02:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "1b2a5922b58c8060844b43e14dfa5b0c8b119f281f54a46f0f1c34accde71ddb"
      tags = "APT, DEMO, FILE, G0034, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cmd = \"cmd.exe /c \" + arg + \" \" + arg2" fullword ascii
      $s2 = "Dim WMI:  Set WMI = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")" fullword ascii
      $s3 = "cmd = \"certutil -encode -f \" + source + \" \" + dest" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x6944 and filesize < 30KB and 1 of them ) or ( 2 of them )
}