rule CN_Honker_sig_3389_2_3389_RID2F07 : CHINA DEMO EXE FILE HKTL T1087_002 {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file 3389.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:39:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1087_002"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "C:\\Documents and Settings\\Administrator\\" ascii
      $s2 = "net user guest /active:yes" fullword ascii
      $s3 = "\\Microsoft Word.exe" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 80KB and all of them
}