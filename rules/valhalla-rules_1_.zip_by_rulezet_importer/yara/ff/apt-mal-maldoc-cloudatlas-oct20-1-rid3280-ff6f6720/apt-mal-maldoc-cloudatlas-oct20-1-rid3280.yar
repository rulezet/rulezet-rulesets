rule APT_MAL_MalDoc_CloudAtlas_Oct20_1_RID3280 : APT DEMO FILE G0100 MAL {
   meta:
      description = "Detects unknown maldoc dropper noticed in October 2020"
      author = "Florian Roth"
      reference = "https://twitter.com/jfslowik/status/1316050637092651009"
      date = "2020-10-13 14:07:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7ba76b2311736dbcd4f2817c40dae78f223366f2404571cd16d6676c7a640d70"
      tags = "APT, DEMO, FILE, G0100, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "https://msofficeupdate.org" wide
   condition: 
      uint16 ( 0 ) == 0xcfd0 and filesize < 300KB and 1 of ( $x* )
}