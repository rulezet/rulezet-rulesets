import "pe"
rule MAL_Floxif_Generic_RID2DCE : DEMO EXE FILE GEN MAL {
   meta:
      description = "Detects Floxif Malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-11 10:47:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085"
      tags = "DEMO, EXE, FILE, GEN, MAL"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and ( pe.imphash ( ) == "2f4ddcfebbcad3bacadc879747151f6f" or pe.exports ( "FloodFix" ) or pe.exports ( "FloodFix2" ) )
}