rule CN_Honker_MSTSC_can_direct_copy_RID32D6 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file MSTSC_can_direct_copy.EXE"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:22:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "srv\\newclient\\lib\\win32\\obj\\i386\\mstsc.pdb" ascii
      $s2 = "Clear Password" fullword wide
      $s3 = "/migrate -- migrates legacy connection files that were created with " fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and all of them
}