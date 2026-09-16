rule APT_APT41_HIGHNOON_RID2C58 : APT DEMO EXE FILE G0096 {
   meta:
      description = "Detects APT41 malware HIGHNOON"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07 09:45:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "63e8ed9692810d562adb80f27bb1aeaf48849e468bf5fd157bc83ca83139b6d7"
      hash2 = "4aa6970cac04ace4a930de67d4c18106cf4004ba66670cfcdaa77a4c4821a213"
      tags = "APT, DEMO, EXE, FILE, G0096"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "workdll64.dll" fullword ascii
      $s1 = "\\Fonts\\Error.log" ascii
      $s2 = "[%d/%d/%d/%d:%d:%d]" fullword ascii
      $s3 = "work_end" fullword ascii
      $s4 = "work_start" fullword ascii
      $s5 = "\\svchost.exe" ascii
      $s6 = "LoadAppInit_DLLs" fullword ascii
      $s7 = "netsvcs" fullword ascii
      $s8 = "HookAPIs ...PID %d " fullword ascii
      $s9 = "SOFTWARE\\Microsoft\\HTMLHelp" fullword ascii
      $s0 = "DllMain_mem" fullword ascii
      $s10 = "%s\\NtKlRes.dat" fullword ascii
      $s11 = "Global\\%s-%d" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and ( 1 of ( $x* ) or 4 of them )
}