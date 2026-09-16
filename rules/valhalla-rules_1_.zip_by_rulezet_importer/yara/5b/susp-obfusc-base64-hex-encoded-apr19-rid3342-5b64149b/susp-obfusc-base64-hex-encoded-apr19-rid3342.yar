rule SUSP_OBFUSC_Base64_Hex_Encoded_Apr19_RID3342 : DEMO FILE OBFUS SUSP T1027 T1132_001 {
   meta:
      description = "Detects hex encoded code that has been base64 encoded"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-04-29 14:40:11"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-12-01"
      tags = "DEMO, FILE, OBFUS, SUSP, T1027, T1132_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = { 78 34 4e ?? ?? 63 65 44 ?? ?? 58 48 67 } 
      $x2 = { 63 45 44 ?? ?? 58 48 67 ?? ?? ?? 78 34 4e } 
      $fp1 = "Microsoft Azure Code Signp$" 
   condition: 
      1 of ( $x* ) and not 1 of ( $fp* )
}