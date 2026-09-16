import "pe"
rule PasswordPro_NTLM_DLL_RID2E6A : DEMO EXE FILE HKTL {
   meta:
      description = "Semiautomatically generated YARA rule - file NTLM.dll"
      author = "Florian Roth"
      reference = "PasswordPro"
      date = "2017-08-27 11:13:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "47d4755d31bb96147e6230d8ea1ecc3065da8e557e8176435ccbcaea16fe50de"
      tags = "DEMO, EXE, FILE, HKTL"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $s1 = "NTLM.dll" fullword ascii
      $s2 = "Algorithm: NTLM" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 20KB and pe.exports ( "GetHash" ) and pe.exports ( "GetInfo" ) and ( all of them ) )
}