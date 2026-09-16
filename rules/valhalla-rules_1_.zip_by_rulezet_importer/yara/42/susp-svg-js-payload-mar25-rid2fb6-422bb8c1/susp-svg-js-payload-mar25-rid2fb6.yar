rule SUSP_SVG_JS_Payload_Mar25_RID2FB6 : DEMO GEN SUSP T1059_007 {
   meta:
      description = "Detects a suspicious SVG file that contains a JavaScript payload. This rule is a generic rule that might generate false positives. A match should be further investigated."
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-03-20 12:08:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-21"
      tags = "DEMO, GEN, SUSP, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "<svg xmlns=" ascii fullword
      $sx1 = "src=\"data:application/ecmascript;base64," 
      $sx2 = "=\"></script>" 
      $ss1 = "<script type=\"application/ecmascript\">" 
      $ss2 = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100%\" height=\"100%\">" 
   condition: 
      $a1 in ( 0 .. 1024 ) and ( filesize < 100KB and 1 of ( $sx* ) or filesize < 1MB and 2 of ( $s* ) )
}