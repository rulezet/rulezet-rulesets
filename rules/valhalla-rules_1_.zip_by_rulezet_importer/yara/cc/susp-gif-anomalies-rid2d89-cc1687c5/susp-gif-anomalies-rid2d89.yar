rule SUSP_GIF_Anomalies_RID2D89 : DEMO FILE OBFUS SUSP {
   meta:
      description = "Detects files with GIF headers and format anomalies - which means that this image could be an obfuscated file of a different type"
      author = "Florian Roth"
      reference = "https://en.wikipedia.org/wiki/GIF"
      date = "2020-07-02 10:36:01"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, OBFUS, SUSP"
      minimum_yara = "3.5.0"
      
   condition: 
      uint16 ( 0 ) == 0x4947 and uint8 ( 2 ) == 0x46 and uint8 ( 11 ) != 0x00 and uint8 ( 12 ) != 0x00 and uint8 ( filesize - 1 ) != 0x3b
}