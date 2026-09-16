rule Kriskynote_Mar17_3_RID2DBD : DEMO EXE FILE MAL T1218_011 {
   meta:
      description = "Detects Kriskynote Malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-03 10:44:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fc838e07834994f25b3b271611e1014b3593278f0703a4a985fb4234936df492"
      tags = "DEMO, EXE, FILE, MAL, T1218_011"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "rundll32 %s Check" fullword ascii
      $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs" fullword ascii
      $s3 = "name=\"IsUserAdmin\"" fullword ascii
      $s4 = "zok]\\\\\\ZZYYY666564444" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 2 of them )
}