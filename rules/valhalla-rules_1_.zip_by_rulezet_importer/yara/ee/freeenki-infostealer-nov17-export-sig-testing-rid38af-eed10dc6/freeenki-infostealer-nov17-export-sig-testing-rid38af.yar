import "pe"
rule Freeenki_Infostealer_Nov17_Export_Sig_Testing_RID38AF : DEMO EXE FILE MAL {
   meta:
      description = "Detects Freenki infostealer malware"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
      date = "2017-11-28 18:31:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5"
      tags = "DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and pe.exports ( "getUpdate" ) and pe.number_of_exports == 1
}