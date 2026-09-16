rule EXPL_JSP_CommVault_CVE_2025_57791_Aug25_2_RID33D2 : CVE_2025_57791 DEMO EXPLOIT {
   meta:
      description = "Detects potential exploit for WT-2025-0049, Post-Auth RCE with QCommand Path Traversal"
      author = "X__Junior"
      reference = "https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/"
      date = "2025-08-21 15:04:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2025_57791, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<App_UpdateUserPropertiesRequest>" ascii
      $s2 = "<description>" ascii
      $s3 = "getMethod('getRuntime').invoke(null).exec(param.cmd)" ascii
   condition: 
      filesize < 50KB and all of them
}