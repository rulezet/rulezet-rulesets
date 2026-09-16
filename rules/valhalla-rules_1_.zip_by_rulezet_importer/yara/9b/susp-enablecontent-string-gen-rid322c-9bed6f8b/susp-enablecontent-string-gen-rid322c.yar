rule SUSP_EnableContent_String_Gen_RID322C : DEMO FILE GEN OFFICE SUSP T1203 T1566_001 {
   meta:
      description = "Detects suspicious string that asks to enable active content in Office Doc"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-02-12 13:53:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "525ba2c8d35f6972ac8fcec8081ae35f6fe8119500be20a4113900fe57d6a0de"
      tags = "DEMO, FILE, GEN, OFFICE, SUSP, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $e1 = "Enable Editing" fullword ascii
      $e2 = "Enable Content" fullword ascii
      $e3 = "Enable editing" fullword ascii
      $e4 = "Enable content" fullword ascii
   condition: 
      uint16 ( 0 ) == 0xcfd0 and ( $e1 in ( 0 .. 3000 ) or $e2 in ( 0 .. 3000 ) or $e3 in ( 0 .. 3000 ) or $e4 in ( 0 .. 3000 ) or 2 of them )
}