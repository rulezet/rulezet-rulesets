rule iam_iamdll_RID2B1A : APT DEMO EXE FILE {
   meta:
      description = "Semiautomatically generated YARA rule - file iamdll.dll"
      author = "Florian Roth"
      reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
      date = "2015-07-10 08:52:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "LSASRV.DLL" fullword ascii
      $s1 = "iamdll.dll" fullword ascii
      $s2 = "ChangeCreds" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 115KB and all of them
}