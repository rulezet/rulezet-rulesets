rule SUSP_PE_Compromised_Certificate_Feb25_RID34C6 : DEMO EXE FILE SUSP T1203 T1566_001 {
   meta:
      description = "Detects suspicious PE files signed with a certificate used in a widespread phishing attack in February 2025"
      author = "Jonathan Peters"
      reference = "https://x.com/DTCERT/status/1890384162818802135"
      date = "2025-02-14 15:44:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-24"
      tags = "DEMO, EXE, FILE, SUSP, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $sb1 = { 44 B8 66 73 57 BB 95 65 1D 61 D0 61 } 
      $sb2 = { 4F 23 43 D9 61 54 B9 41 DB 0A 26 B2 } 
      $sb3 = { 40 A3 62 E3 50 68 91 19 F5 2E C3 4C } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 20MB and 1 of them
}