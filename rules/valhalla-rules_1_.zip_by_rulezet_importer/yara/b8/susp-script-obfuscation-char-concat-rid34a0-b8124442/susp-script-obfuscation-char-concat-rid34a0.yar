rule SUSP_Script_Obfuscation_Char_Concat_RID34A0 : CHINA DEMO OBFUS SCRIPT SUSP {
   meta:
      description = "Detects strings found in sample from CN group repo leak in October 2018"
      author = "Florian Roth"
      reference = "https://twitter.com/JaromirHorejsi/status/1047084277920411648"
      date = "2018-10-04 15:38:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b30cc10e915a23c7273f0838297e0d2c9f4fc0ac1f56100eef6479c9d036c12b"
      tags = "CHINA, DEMO, OBFUS, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\"c\" & \"r\" & \"i\" & \"p\" & \"t\"" ascii
   condition: 
      1 of them
}