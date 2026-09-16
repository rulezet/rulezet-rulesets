rule CN_Honker_sig_3389_xp3389_RID2F5E : CHINA DEMO EXE FILE HKTL T1543_003 {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file xp3389.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:54:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1543_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "echo \"fdenytsconnections\"=dword:00000000 >> c:\\reg.reg" fullword ascii
      $s2 = "echo [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server] >" ascii
      $s3 = "echo \"Tsenabled\"=dword:00000001 >> c:\\reg.reg" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 20KB and all of them
}