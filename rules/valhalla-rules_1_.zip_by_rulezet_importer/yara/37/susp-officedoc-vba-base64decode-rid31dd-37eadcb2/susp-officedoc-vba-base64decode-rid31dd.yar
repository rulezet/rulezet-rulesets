rule SUSP_OfficeDoc_VBA_Base64Decode_RID31DD : DEMO FILE SCRIPT SUSP T1132_001 {
   meta:
      description = "Detects suspicious VBA code with Base64 decode functions"
      author = "Florian Roth"
      reference = "https://github.com/cpaton/Scripting/blob/master/VBA/Base64.bas"
      date = "2019-06-21 13:40:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "52262bb315fa55b7441a04966e176b0e26b7071376797e35c80aa60696b6d6fc"
      tags = "DEMO, FILE, SCRIPT, SUSP, T1132_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "B64_CHAR_DICT" ascii
      $s2 = "Base64Decode" ascii
      $s3 = "Base64Encode" ascii
   condition: 
      uint16 ( 0 ) == 0xcfd0 and filesize < 60KB and 2 of them
}