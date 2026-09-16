rule Sniffer_analyzer_SSClone_1210_full_version_RID3733 : CHINA DEMO EXE FILE HKTL T1040 {
   meta:
      description = "Chinese Hacktool Set - file Sniffer analyzer SSClone 1210 full version.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 17:28:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1040"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "http://www.vip80000.com/hot/index.html" fullword ascii
      $s1 = "GetConnectString" fullword ascii
      $s2 = "CnCerT.Safe.SSClone.dll" fullword ascii
      $s3 = "(*.JPG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.BMP;*.GIF;*.ICO;*.CUR|JPG" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3580KB and all of them
}