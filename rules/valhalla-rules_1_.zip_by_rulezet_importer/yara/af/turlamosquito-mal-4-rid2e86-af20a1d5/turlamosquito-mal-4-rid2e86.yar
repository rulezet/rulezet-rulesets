import "pe"
rule TurlaMosquito_Mal_4_RID2E86 : DEMO EXE FILE G0010 MAL RUSSIA {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22 11:18:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b362b235539b762734a1833c7e6c366c1b46474f05dc17b3a631b3bff95a5eec"
      tags = "DEMO, EXE, FILE, G0010, MAL, RUSSIA"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 800KB and pe.imphash ( ) == "17b328245e2874a76c2f46f9a92c3bad"
}