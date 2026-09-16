rule SVG_LoadURL_RID2AD3 : DEMO EXPLOIT {
   meta:
      description = "Detects a tiny SVG file that loads an URL (as seen in CryptoWall malware infections)"
      author = "Florian Roth"
      reference = "https://www.appriver.com/resources/blog"
      date = "2015-05-24 08:43:21"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "</svg>" nocase
      $s2 = "<script>" nocase
      $s3 = "location.href='http" nocase
   condition: 
      filesize < 600 and all of ( $s* )
}