rule SUSP_EXPL_CommVault_CVE_2025_57791_Artifact_Aug25_RID372C : CVE_2025_57791 DEMO EXPLOIT SUSP {
   meta:
      description = "Detects exploit artifact for WT-2025-0050, authentication bypass through QCommand argument injection"
      author = "X__Junior"
      reference = "https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/"
      date = "2025-08-21 17:27:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2025_57791, DEMO, EXPLOIT, SUSP"
      minimum_yara = "4.0.0"
      
   strings:
      $sa1 = "_localadmin__" 
      $sa2 = /-cs [a-zA-Z0-9-{}]{3,32} -cs / 
      $sb2 = "-localadmin" base64
      $sb1 = "-localadmin" 
   condition: 
      filesize < 20MB and all of ( $sa* ) and 1 of ( $sb* )
}