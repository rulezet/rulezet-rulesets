rule GlassRAT_Generic_RID2D0E : DEMO EXE FILE GEN MAL T1218_011 T1543_003 {
   meta:
      description = "Detects GlassRAT Malware"
      author = "Florian Roth"
      reference = "https://blogs.rsa.com/peering-into-glassrat/"
      date = "2015-11-23 10:15:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "30d26aebcee21e4811ff3a44a7198a5c519843a24f334880384a7158e07ae399"
      hash2 = "3bdeb3805e9230361fb93c6ffb0bfec8d3aee9455d95b2428c7f6292d387d3a4"
      hash3 = "79993f1912958078c4d98503e00dc526eb1d0ca4d020d17b010efa6c515ca92e"
      tags = "DEMO, EXE, FILE, GEN, MAL, T1218_011, T1543_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cmd.exe /c %s" fullword ascii
      $s2 = "update.dll" fullword ascii
      $s3 = "SYSTEM\\CurrentControlSet\\Services\\RasAuto\\Parameters" fullword ascii
      $s4 = "%%temp%%\\%u" fullword ascii
      $s5 = "\\off.dat" ascii
      $s6 = "rundll32 \"%s\",AddNum" fullword ascii
      $s7 = "cmd.exe /c erase /F \"%s\"" fullword ascii
      $s8 = "SYSTEM\\ControlSet00%d\\Services\\RasAuto" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 15MB and 5 of them
}