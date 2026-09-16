rule Casper_Included_Strings_RID303F : APT DEMO EXE FILE T1082 {
   meta:
      description = "Casper French Espionage Malware - String Match in File - https://www.welivesecurity.com/2015/03/05/casper-malware-babar-bunny-another-espionage-cartoon/"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2015/03/05/casper-malware-babar-bunny-another-espionage-cartoon/"
      date = "2015-03-06 12:31:41"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, EXE, FILE, T1082"
      minimum_yara = "3.5.0"
      
   strings:
      $a0 = "cmd.exe /C FOR /L %%i IN (1,1,%d) DO IF EXIST" 
      $a1 = "& SYSTEMINFO) ELSE EXIT" 
      $c1 = "domcommon.exe" wide fullword
      $c2 = "jpic.gov.sy" fullword
      $c3 = "aiomgr.exe" wide fullword
      $c4 = "perfaudio.dat" fullword
      $c5 = "Casper_DLL.dll" fullword
      $c6 = { 7B 4B 59 DE 37 4A 42 26 59 98 63 C6 2D 0F 57 40 } 
      $c7 = "{4216567A-4512-9825-7745F856}" fullword
   condition: 
      all of ( $a* ) or ( uint16 ( 0 ) == 0x5a4d and 1 of ( $c* ) )
}