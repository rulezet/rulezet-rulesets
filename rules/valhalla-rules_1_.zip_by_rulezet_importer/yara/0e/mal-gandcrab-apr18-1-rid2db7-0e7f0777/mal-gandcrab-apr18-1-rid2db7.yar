import "pe"
rule MAL_GandCrab_Apr18_1_RID2DB7 : DEMO EXE FILE MAL {
   meta:
      description = "Detects GandCrab malware"
      author = "Florian Roth"
      reference = "https://twitter.com/MarceloRivero/status/988455516094550017"
      date = "2018-04-23 10:43:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6fafe7bb56fd2696f2243fc305fe0c38f550dffcfc5fca04f70398880570ffff"
      tags = "DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 800KB and pe.imphash ( ) == "7936b0e9491fd747bf2675a7ec8af8ba"
}