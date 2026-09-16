rule SUSP_Microsoft_Copyright_String_Anomaly_2_RID3720 : ANOMALY DEMO EXE FILE SUSP {
   meta:
      description = "Detects Floxif Malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-11 17:25:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085"
      tags = "ANOMALY, DEMO, EXE, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Microsoft(C) Windows(C) Operating System" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them
}