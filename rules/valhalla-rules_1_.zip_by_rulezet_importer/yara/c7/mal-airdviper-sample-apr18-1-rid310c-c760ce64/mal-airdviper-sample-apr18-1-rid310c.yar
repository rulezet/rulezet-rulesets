rule MAL_AirdViper_Sample_Apr18_1_RID310C : APT DEMO EXE FILE G1028 MAL MIDDLE_EAST {
   meta:
      description = "Detects Arid Viper malware sample"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-04 13:05:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9f453f1d5088bd17c60e812289b4bb0a734b7ad2ba5a536f5fd6d6ac3b8f3397"
      tags = "APT, DEMO, EXE, FILE, G1028, MAL, MIDDLE_EAST"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"%s\"" fullword ascii
      $x2 = "daenerys=%s&" ascii
      $x3 = "betriebssystem=%s&anwendung=%s&AV=%s" ascii
      $s1 = "Taskkill /IM  %s /F &  %s" fullword ascii
      $s2 = "/api/primewire/%s/requests/macKenzie/delete" fullword ascii
      $s3 = "\\TaskWindows.exe" ascii
      $s4 = "MicrosoftOneDrives.exe" fullword ascii
      $s5 = "\\SeanSansom.txt" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 6000KB and ( 1 of ( $x* ) or 4 of them )
}