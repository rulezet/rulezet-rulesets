rule Regin_sig_svcsstat_RID2E82 : APT DEMO FILE regin {
   meta:
      description = "Detects svcstat from Regin report - file svcsstat.exe_sample"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-25 11:17:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "APT, DEMO, FILE, regin"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Service Control Manager" fullword ascii
      $s1 = "_vsnwprintf" ascii
      $s2 = "Root Agency" fullword ascii
      $s3 = "Root Agency0" fullword ascii
      $s4 = "StartServiceCtrlDispatcherA" fullword ascii
      $s5 = "\\\\?\\UNC" fullword wide
      $s6 = "%ls%ls" fullword wide
   condition: 
      filesize < 15KB and filesize > 10KB and all of them
}