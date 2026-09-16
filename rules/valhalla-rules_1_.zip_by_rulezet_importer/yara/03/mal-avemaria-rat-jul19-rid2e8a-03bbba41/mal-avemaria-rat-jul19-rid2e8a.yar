rule MAL_AveMaria_RAT_Jul19_RID2E8A : AveMaria DEMO EXE FILE MAL {
   meta:
      description = "Detects AveMaria RAT"
      author = "Florian Roth"
      reference = "https://twitter.com/abuse_ch/status/1145697917161934856"
      date = "2019-07-01 11:18:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5a927db1566468f23803746ba0ccc9235c79ca8672b1444822631ddbf2651a59"
      tags = "AveMaria, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "operator co_await" fullword ascii
      $s1 = "uohlyatqn" fullword ascii
      $s2 = "index = [%d][%d][%d][%d]" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and all of them
}