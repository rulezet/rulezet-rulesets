rule Generic_KeyGen_Patcher_RID2F96 : CHINA DEMO EXE FILE GEN HKTL {
   meta:
      description = "Keygen from CN Honker Pentest Toolset - file Acunetix_Web_Vulnerability_Scanner_8.x_Enterprise_Edition_KeyGen.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:03:31"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, GEN, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<description>Patch</description>" fullword ascii
      $s2 = "\\dup2patcher.dll" ascii
      $s3 = "load_patcher" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 4000KB and all of them
}