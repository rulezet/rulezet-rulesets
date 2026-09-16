import "pe"
rule TurlaMosquito_Mal_1_RID2E83 : DEMO EXE FILE G0010 MAL RUSSIA {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22 11:17:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b295032919143f5b6b3c87ad22bcf8b55ecc9244aa9f6f88fc28f36f5aa2925e"
      tags = "DEMO, EXE, FILE, G0010, MAL, RUSSIA"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Pipetp" fullword ascii
      $s2 = "EStOpnabn" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and ( pe.imphash ( ) == "169d4237c79549303cca870592278f42" or all of them )
}