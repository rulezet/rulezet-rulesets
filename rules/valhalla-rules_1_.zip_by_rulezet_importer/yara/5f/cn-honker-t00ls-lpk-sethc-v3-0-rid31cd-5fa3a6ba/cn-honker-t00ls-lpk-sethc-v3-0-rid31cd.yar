rule CN_Honker_T00ls_Lpk_Sethc_v3_0_RID31CD : CHINA DEMO EXE FILE HKTL T1546_008 {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file T00ls Lpk Sethc v3.0.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:38:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1546_008"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "http://127.0.0.1/1.exe" fullword wide
      $s2 = ":Rices  Forum:T00Ls.Net  [4 Fucker Te@m]" fullword wide
      $s3 = "SkinH_EL.dll" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 2 of them
}