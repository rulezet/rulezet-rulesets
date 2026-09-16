rule GoodToolset_pr_RID2CC5 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file pr.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:03:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "-->Got WMI process Pid: %d " ascii
      $s2 = "-->This exploit gives you a Local System shell " ascii
      $s3 = "wmiprvse.exe" fullword ascii
      $s4 = "Try the first %d time" fullword ascii
      $s5 = "-->Build&&Change By p " ascii
      $s6 = "root\\MicrosoftIISv2" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them
}