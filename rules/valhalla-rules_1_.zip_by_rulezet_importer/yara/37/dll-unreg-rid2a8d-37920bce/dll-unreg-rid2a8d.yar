rule dll_UnReg_RID2A8D : APT CHINA DEMO SCRIPT T1218_010 {
   meta:
      description = "Chinese Hacktool Set - file UnReg.bat"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 06:46:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, SCRIPT, T1218_010"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "regsvr32.exe /u C:\\windows\\system32\\PacketX.dll" fullword ascii
      $s1 = "del /F /Q C:\\windows\\system32\\PacketX.dll" fullword ascii
   condition: 
      filesize < 1KB and 1 of them
}