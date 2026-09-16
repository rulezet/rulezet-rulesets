rule GoldDragon_RunnignRAT_RID2F19 : APT CHINA CRIME DEMO EXE FILE T1057 T1082 T1218_011 {
   meta:
      description = "Detects Running RAT malware from Gold Dragon report"
      author = "Florian Roth"
      reference = "https://www.mcafee.com:443/blogs/"
      date = "2018-02-03 11:42:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "94aa827a514d7aa70c404ec326edaaad4b2b738ffaea5a66c0c9f246738df579"
      hash2 = "5cbc07895d099ce39a3142025c557b7fac41d79914535ab7ffc2094809f12a4b"
      hash3 = "98ccf3a463b81a47fdf4275e228a8f2266e613e08baae8bdcd098e49851ed49a"
      tags = "APT, CHINA, CRIME, DEMO, EXE, FILE, T1057, T1082, T1218_011"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cmd.exe /c systeminfo " fullword ascii
      $s2 = "ieproxy.dll" fullword ascii
      $s3 = "taskkill /f /im daumcleaner.exe" fullword ascii
      $s4 = "cmd.exe /c tasklist " fullword ascii
      $s5 = "rundll32.exe \"%s\" Run" fullword ascii
      $s6 = "Mozilla/5.0 (Windows NT 5.2; rv:12.0) Gecko/20100101 Firefox/12.0" fullword ascii
      $s7 = "%s\\%s_%03d" fullword wide
      $s8 = "\\PI_001.dat" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and ( 3 of them )
}