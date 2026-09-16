rule HKTL_EXPL_POC_LibSSH_Auth_Bypass_CVE_2023_2283_Jun23_1_RID3855 : CVE_2023_2283 DEMO EXPLOIT FILE HKTL {
   meta:
      description = "Detects POC code used in attacks against libssh vulnerability CVE-2023-2283"
      author = "Florian Roth"
      reference = "https://github.com/github/securitylab/tree/1786eaae7f90d87ce633c46bbaa0691d2f9bf449/SecurityExploits/libssh/pubkey-auth-bypass-CVE-2023-2283"
      date = "2023-06-08 18:16:41"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2023_2283, DEMO, EXPLOIT, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "nprocs = %d" ascii fullword
      $s2 = "fork failed: %s" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x457f and all of them
}