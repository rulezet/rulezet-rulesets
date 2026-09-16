rule SUSP_OBFUSC_Indiators_XML_OfficeDoc_Sep21_2_RID3615 : CVE DEMO OBFUS OFFICE SUSP T1027 T1203 T1566_001 Windows {
   meta:
      description = "Detects suspicious encodings in fields used in reference files found in weaponized MS Office documents"
      author = "Florian Roth"
      reference = "https://twitter.com/sudosev/status/1439205606129377282"
      date = "2021-09-18 16:40:41"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE, DEMO, OBFUS, OFFICE, SUSP, T1027, T1203, T1566_001, Windows"
      minimum_yara = "3.5.0"
      
   strings:
      $h1 = "<?xml " ascii wide
      $a1 = "Target" ascii wide
      $a2 = "TargetMode" ascii wide
      $xml_e = "&#x0000" ascii wide
   condition: 
      filesize < 500KB and all of them
}