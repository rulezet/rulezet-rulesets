rule Jc_ALL_WinEggDropShell_rar_Folder_Install_2 {
   meta:
      description = "Disclosed hacktool set (old stuff) - file Install.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "95866e917f699ee74d4735300568640ea1a05afd"
      id = "ebfc8e53-328c-5deb-bf9b-e0270f171c68"
   strings:
      $s1 = "http://go.163.com/sdemo" fullword wide
      $s2 = "Player.tmp" fullword ascii
      $s3 = "Player.EXE" fullword wide
      $s4 = "mailto:sdemo@263.net" fullword ascii
      $s5 = "S-Player.exe" fullword ascii
      $s9 = "http://www.BaiXue.net (" wide
   condition:
      all of them
}