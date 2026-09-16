rule EXPL_MacOS_Switcharoo_Indicator_Dec22_RID34A9 : CVE_2022_46689 DEMO EXPLOIT MACOS {
   meta:
      description = "Detects indicators found after exploitations of CVE-2022-46689"
      author = "Florian Roth"
      reference = "https://github.com/zhuowei/MacDirtyCowDemo"
      date = "2022-12-19 15:40:01"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2022_46689, DEMO, EXPLOIT, MACOS"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "auth       sufficient     pam_permit.so" ascii
   condition: 
      filesize < 1KB and $x1
}