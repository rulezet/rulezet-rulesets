rule SUSP_OBFUSC_SH_Indicators_Apr24_1_RID325E : DEMO FILE OBFUS SCRIPT SUSP T1027 {
   meta:
      description = "Detects characteristics found in obfuscated script (used in the backdoored XZ package, but could match on others, too)"
      author = "Florian Roth"
      reference = "https://www.openwall.com/lists/oss-security/2024/03/29/4/1"
      date = "2024-04-06 14:02:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-24"
      tags = "DEMO, FILE, OBFUS, SCRIPT, SUSP, T1027"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "eval $" 
   condition: 
      uint8 ( 1 ) == 0x3d and $s1 in ( filesize - 20 .. filesize )
}