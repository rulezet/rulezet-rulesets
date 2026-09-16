rule CN_Honker_getlsasrvaddr_RID303D : CHINA DEMO EXE FILE HKTL T1003 {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file getlsasrvaddr.exe - WCE Amplia Security"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:31:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "pingme.txt" fullword ascii
      $s16 = ".\\lsasrv.pdb" ascii
      $s20 = "Addresses Found: " fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them
}