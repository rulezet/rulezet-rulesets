rule SUSP_RAR_with_PDF_Script_Obfuscation_RID34A4 : DEMO FILE OBFUS SCRIPT SUSP {
   meta:
      description = "Detects RAR file with suspicious .pdf extension prefix to trick users"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-04-06 15:39:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b629b46b009a1c2306178e289ad0a3d9689d4b45c3d16804599f23c90c6bca5b"
      tags = "DEMO, FILE, OBFUS, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".pdf.vbe" ascii
      $s2 = ".pdf.vbs" ascii
      $s3 = ".pdf.ps1" ascii
      $s4 = ".pdf.bat" ascii
      $s5 = ".pdf.exe" ascii
   condition: 
      uint32 ( 0 ) == 0x21726152 and 1 of them
}