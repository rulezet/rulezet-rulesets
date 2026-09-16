import "pe"
rule TurlaMosquito_Mal_5_RID2E87 : DEMO EXE FILE G0010 MAL RUSSIA {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22 11:18:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "26a1a42bc74e14887616f9d6048c17b1b4231466716a6426e7162426e1a08030"
      tags = "DEMO, EXE, FILE, G0010, MAL, RUSSIA"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and pe.imphash ( ) == "ac40cf7479f53a4754ac6481a4f24e57"
}