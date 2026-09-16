rule MAL_JRAT_Oct18_1_RID2BF9 : DEMO FILE MAL {
   meta:
      description = "Detects JRAT malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-10-11 09:29:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ce190c37a6fdb2632f4bc5ea0bb613b3fbe697d04e68e126b41910a6831d3411"
      tags = "DEMO, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "/JRat.class" ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 700KB and 1 of them
}