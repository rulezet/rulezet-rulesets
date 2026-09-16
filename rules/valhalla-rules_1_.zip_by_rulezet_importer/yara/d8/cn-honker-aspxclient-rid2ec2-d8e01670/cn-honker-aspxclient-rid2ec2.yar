rule CN_Honker_AspxClient_RID2EC2 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file AspxClient.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:28:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\tools\\hashq\\hashq.exe" wide
      $s2 = "\\Release\\CnCerT.CCdoor.Client.pdb" ascii
      $s3 = "\\myshell.mdb" wide
      $s4 = "injectfile" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 3 of them
}