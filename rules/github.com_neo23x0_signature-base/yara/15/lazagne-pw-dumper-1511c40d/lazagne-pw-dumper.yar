rule Lazagne_PW_Dumper {
   meta:
      description = "Detects Lazagne PW Dumper"
      author = "Markus Neis / Florian Roth"
      reference = "https://github.com/AlessandroZ/LaZagne/releases/"
      date = "2018-03-22"
      score = 70
      id = "1904029e-9336-5278-ae2e-4bc853316600"
   strings:
      $s1 = "Crypto.Hash" fullword ascii
      $s2 = "laZagne" fullword ascii
      $s3 = "impacket.winregistry" fullword ascii
   condition:
      3 of them
}