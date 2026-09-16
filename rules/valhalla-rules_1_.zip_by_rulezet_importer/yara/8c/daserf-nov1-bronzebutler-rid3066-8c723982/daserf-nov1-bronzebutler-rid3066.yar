rule Daserf_Nov1_BronzeButler_RID3066 : CHINA DEMO EXE FILE G0060 MAL daserf {
   meta:
      description = "Detects Daserf malware used by Bronze Butler"
      author = "Florian Roth"
      reference = "http://127.0.0.1"
      date = "2017-11-08 12:38:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "5ede6f93f26ccd6de2f93c9bd0f834279df5f5cfe3457915fae24a3aec46961b"
      tags = "CHINA, DEMO, EXE, FILE, G0060, MAL, daserf"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "mstmp1845234.exe" fullword ascii
      $x2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; SV1)" fullword ascii
      $x3 = "Mozilla/4.0 (compatible; MSIE 11.0; Windows NT 6.1; SV1)" fullword ascii
      $s1 = "Content-Type: */*" fullword ascii
      $s2 = "ProxyEnable" ascii fullword
      $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" ascii fullword
      $s4 = "iexplore.exe" ascii fullword
      $s5 = "\\SOFTWARE\\Microsoft\\Windows\\Cu" ascii
      $s6 = "rrentVersion\\Internet Settings" fullword ascii
      $s7 = "ws\\CurrentVersion\\Inter" fullword ascii
      $s8 = "Documents an" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and ( 1 of ( $x* ) or 5 of them )
}