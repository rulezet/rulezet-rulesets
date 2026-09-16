rule CoinMiner_Strings_RID2DDE : DEMO HIGHVOL SCRIPT SUSP {
   meta:
      description = "Detects mining pool protocol string in Executable"
      author = "Florian Roth"
      reference = "https://minergate.com/faq/what-pool-address"
      date = "2018-01-04 10:50:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2021-10-26"
      tags = "DEMO, HIGHVOL, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = "stratum+tcp://" ascii
      $sa2 = "stratum+udp://" ascii
      $sb1 = "\"normalHashing\": true," 
   condition: 
      filesize < 3000KB and 1 of them
}