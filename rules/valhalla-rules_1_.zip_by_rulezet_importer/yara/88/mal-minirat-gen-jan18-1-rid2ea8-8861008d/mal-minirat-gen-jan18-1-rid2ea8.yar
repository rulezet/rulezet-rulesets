rule MAL_MiniRAT_Gen_Jan18_1_RID2EA8 : DEMO EXE FILE GEN MAL {
   meta:
      description = "Detects Mini RAT malware inidcators"
      author = "Florian Roth"
      reference = "https://www.eff.org/deeplinks/2018/01/dark-caracal-good-news-and-bad-news"
      date = "2018-01-22 11:23:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-05-12"
      hash1 = "091ae8d5649c4e040d25550f2cdf7f1ddfc9c698e672318eb1ab6303aa1cf85b"
      hash2 = "b6ac374f79860ae99736aaa190cce5922a969ab060d7ae367dbfa094bfe4777d"
      hash3 = "ba4e063472a2559b4baa82d5272304a1cdae6968145c5ef221295c90e88458e2"
      tags = "DEMO, EXE, FILE, GEN, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\Mini rat\\" ascii
      $x2 = "\\Projects\\ali\\Clever Components v7\\" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 7000KB and 1 of them
}