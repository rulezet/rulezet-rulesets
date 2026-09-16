rule APT_APT29_NOBELIUM_JS_EnvyScout_May21_2_RID33E4 : APT DEMO G0016 G0118 RUSSIA T1059_007 {
   meta:
      description = "Detects EnvyScout deobfuscator code as used by NOBELIUM group"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
      date = "2021-05-29 15:07:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, G0016, G0118, RUSSIA, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "saveAs(blob, " ascii
      $s2 = ".iso\");" ascii
      $s3 = "application/x-cd-image" ascii
      $s4 = ".indexOf(\"Win\")!=-1" ascii
   condition: 
      filesize < 5000KB and all of them
}