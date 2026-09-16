rule Dll_LoadEx_RID2AC9 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file Dll_LoadEx_RID2AC9.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:26:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "WiNrOOt@126.com" fullword wide
      $s1 = "Dll_LoadEx_RID2AC9.EXE" fullword wide
      $s3 = "You Already Loaded This DLL ! :(" ascii
      $s10 = "Dll_LoadEx_RID2AC9 Microsoft " fullword wide
      $s17 = "Can't Load This Dll ! :(" ascii
      $s18 = "WiNrOOt" fullword wide
      $s20 = " Dll_LoadEx_RID2AC9(&A)..." fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 120KB and 3 of them
}