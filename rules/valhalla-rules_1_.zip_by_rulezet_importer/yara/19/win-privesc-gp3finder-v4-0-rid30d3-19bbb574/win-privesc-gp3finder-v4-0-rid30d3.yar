rule Win_PrivEsc_gp3finder_v4_0_RID30D3 : DEMO EXE FILE HKTL T1068 {
   meta:
      description = "Detects a tool that can be used for privilege escalation - file gp3finder_v4.0.exe"
      author = "Florian Roth"
      reference = "http://grimhacker.com/2015/04/10/gp3finder-group-policy-preference-password-finder/"
      date = "2016-06-02 12:56:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7d34e214ef2ca33516875fb91a72d5798f89b9ea8964d3990f99863c79530c06"
      tags = "DEMO, EXE, FILE, HKTL, T1068"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Check for and attempt to decrypt passwords on share" ascii
      $x2 = "Failed to auto get and decrypt passwords. {0}s/" fullword ascii
      $x3 = "GPPPFinder - Group Policy Preference Password Finder" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and 1 of ( $x* ) ) or ( all of them )
}