rule APT_APT29_NOBELIUM_LNK_NV_Link_May21_2_RID330D : APT DEMO G0016 G0118 RUSSIA T1547_009 {
   meta:
      description = "Detects NV Link as used by NOBELIUM group"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
      date = "2021-05-29 14:31:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, G0016, G0118, RUSSIA, T1547_009"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "RegisterOCX BOOM" ascii wide
      $s2 = "cmd.exe /c start BOOM.exe" ascii wide
   condition: 
      filesize < 5000KB and 1 of them
}