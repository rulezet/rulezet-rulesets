rule HKTL_CN_dat_xpf_RID2C79 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file xpf.sys"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:50:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "UnHook IoGetDeviceObjectPointer ok!" fullword ascii
      $s2 = "\\Device\\XScanPF" wide
      $s3 = "\\DosDevices\\XScanPF" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 25KB and all of them
}