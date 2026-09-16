rule SUSP_EXPL_CommVault_CVE_2025_57791_Aug25_1_RID342F : CVE_2025_57791 DEMO EXE EXPLOIT FILE SUSP {
   meta:
      description = "Detects potential exploit for WT-2025-0050, authentication bypass through QCommand argument injection"
      author = "X__Junior"
      reference = "https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/"
      date = "2025-08-21 15:19:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2025_57791, DEMO, EXE, EXPLOIT, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = "_localadmin__" 
      $sa2 = "-localadmin" 
   condition: 
      not uint16 ( 0 ) == 0x5a4d and filesize < 20MB and all of them
}