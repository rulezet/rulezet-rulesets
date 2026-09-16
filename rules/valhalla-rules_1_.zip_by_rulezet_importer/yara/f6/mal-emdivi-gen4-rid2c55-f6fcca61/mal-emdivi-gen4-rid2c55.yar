rule MAL_Emdivi_Gen4_RID2C55 : DEMO EXE FILE MAL emdivi {
   meta:
      description = "Detects Emdivi Malware"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
      date = "2015-08-20 09:44:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "008f4f14cf64dc9d323b6cb5942da4a99979c4c7d750ec1228d8c8285883771e"
      hash2 = "17e646ca2558a65ffe7aa185ba75d5c3a573c041b897355c2721e9a8ca5fee24"
      hash3 = "3553c136b4eba70eec5d80abe44bd7c7c33ab1b65de617dbb7be5025c9cf01f1"
      tags = "DEMO, EXE, FILE, MAL, emdivi"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".http_port\", " fullword wide
      $s2 = "UserAgent: " fullword ascii
      $s3 = "AUTH FAILED" fullword ascii
      $s4 = "INVALID FILE PATH" fullword ascii
      $s5 = ".autoconfig_url\", \"" fullword wide
      $s6 = "FAILED TO WRITE FILE" fullword ascii
      $s7 = ".proxy" fullword wide
      $s8 = "AuthType: " fullword ascii
      $s9 = ".no_proxies_on\", \"" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 853KB and all of them
}