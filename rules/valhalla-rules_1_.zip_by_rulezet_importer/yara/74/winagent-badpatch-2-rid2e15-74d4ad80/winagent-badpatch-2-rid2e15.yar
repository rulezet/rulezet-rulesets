rule WinAgent_BadPatch_2_RID2E15 : APT DEMO EXE FILE {
   meta:
      description = "Detects samples mentioned in BadPatch report"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2017/10/unit42-badpatch/"
      date = "2017-10-20 10:59:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "106deff16a93c4a4624fe96e3274e1432921c56d5a430834775e5b98861c00ea"
      hash2 = "ece76fdf7e33d05a757ef5ed020140d9367c7319022a889923bbfacccb58f4d7"
      hash3 = "cf53fc8c9ce4e5797cc5ac6f71d4cbc0f2b15f2ed43f38048a5273f40bc09876"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "myAction=shell_result&serialNumber=" fullword wide
      $s2 = "\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\Login Data.*" wide
      $s3 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles" wide
      $s4 = "\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\Cookies.*" wide
      $s5 = "newSHELL[" fullword wide
      $s6 = "\\file1.txt" wide
      $s7 = "myAction=newGIF&serialNumber=" fullword wide
      $s8 = "\\Storege1" wide
      $s9 = "\\Microsoft\\mac.txt" wide
      $s10 = "spytube____:" fullword ascii
      $s11 = "0D0700045F5C5B0312045A04041F40014B1D11004A1F19074A141100011200154B031C04" fullword wide
      $s12 = "16161A1000012B162503151851065A1A0007" fullword wide
      $s13 = "-- SysFile...." fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 700KB and 3 of them )
}