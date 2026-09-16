rule TurlaMosquito_Mal_6_RID2E88 : DEMO EXE FILE G0010 MAL RUSSIA {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22 11:18:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b79cdf929d4a340bdd5f29b3aeccd3c65e39540d4529b64e50ebeacd9cdee5e9"
      tags = "DEMO, EXE, FILE, G0010, MAL, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "/scripts/m/query.php?id=" fullword wide
      $a2 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" fullword wide
      $a3 = "GetUserNameW fails" fullword wide
      $s1 = "QVSWQQ" fullword ascii
      $s2 = "SRRRQP" fullword ascii
      $s3 = "QSVVQQ" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and ( 2 of ( $a* ) or 4 of them )
}