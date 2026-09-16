rule APT_SH_CodeCov_Hack_Apr21_1_RID303D : APT DEMO FILE SCRIPT T1059_004 {
   meta:
      description = "Detects manipulated Codecov bash uploader tool that has been manipulated by an unknown actor during March / April 2021"
      author = "Florian Roth"
      reference = "https://about.codecov.io/security-update/"
      date = "2021-04-16 12:31:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, SCRIPT, T1059_004"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "Global report uploading tool for Codecov" 
      $s1 = "curl -sm 0.5 -d" 
   condition: 
      uint16 ( 0 ) == 0x2123 and filesize < 70KB and all of them
}