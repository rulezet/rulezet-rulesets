rule CN_Honker_sig_3389_mstsc_MSTSCAX_RID324B : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file MSTSCAX.DLL"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:59:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ResetPasswordWWWx" fullword ascii
      $s2 = "Terminal Server Redirected Printer Doc" fullword wide
      $s3 = "Cleaning temp directory" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}