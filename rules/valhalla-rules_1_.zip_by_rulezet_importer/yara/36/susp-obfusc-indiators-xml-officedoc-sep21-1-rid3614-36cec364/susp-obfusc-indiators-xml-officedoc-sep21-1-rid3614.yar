rule SUSP_OBFUSC_Indiators_XML_OfficeDoc_Sep21_1_RID3614 : DEMO OBFUS OFFICE SUSP T1027 T1203 T1566_001 {
   meta:
      description = "Detects suspicious encodings in fields used in reference files found in weaponized MS Office documents"
      author = "Florian Roth"
      reference = "-"
      date = "2021-09-18 16:40:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, OBFUS, OFFICE, SUSP, T1027, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $h1 = "<?xml " ascii wide
      $xml_e = "Target=\"&#" ascii wide
      $xml_mode_1 = "TargetMode=\"&#" ascii wide
   condition: 
      filesize < 500KB and $h1 and 1 of ( $xml* )
}