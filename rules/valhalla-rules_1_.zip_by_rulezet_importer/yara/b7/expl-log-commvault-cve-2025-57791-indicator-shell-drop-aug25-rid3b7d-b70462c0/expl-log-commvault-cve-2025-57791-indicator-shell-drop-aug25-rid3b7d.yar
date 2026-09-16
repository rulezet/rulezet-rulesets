rule EXPL_LOG_CommVault_CVE_2025_57791_Indicator_Shell_Drop_Aug25_RID3B7D : CVE_2025_57791 DEMO EXPLOIT LOG SCRIPT T1505_003 {
   meta:
      description = "Detects suspicious log lines that indicate web shell drops into the Apache root folder of a Commvault installation"
      author = "Florian Roth"
      reference = "https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/"
      date = "2025-08-21 20:31:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2025_57791, DEMO, EXPLOIT, LOG, SCRIPT, T1505_003"
      minimum_yara = "3.5.0"
      
   strings:
      $xr1 = /Results written to \[[C-Z]:\\Program Files\\Commvault\\ContentStore\\Apache\\webapps\\ROOT\\[^\\]{1,20}\.jsp\]/ 
   condition: 
      $xr1
}