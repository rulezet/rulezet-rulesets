rule SUSP_EXPL_CommVault_CVE_2025_57791_Aug25_2_RID3430 : CVE_2025_57791 DEMO EXPLOIT SUSP {
   meta:
      description = "Detects potential exploit for WT-2025-0050, authentication bypass through QCommand argument injection"
      author = "X__Junior"
      reference = "https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/"
      date = "2025-08-21 15:19:51"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2025_57791, DEMO, EXPLOIT, SUSP"
      minimum_yara = "4.0.0"
      
   strings:
      $sa1 = "_localadmin__" 
      $sa2 = "-localadmin" base64
   condition: 
      filesize < 20MB and all of them
}