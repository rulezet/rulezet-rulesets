rule CN_Actor_AmmyyAdmin {
   meta:
      description = "Detects Ammyy Admin Downloader"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - CN Actor"
      date = "2017-06-22"
      score = 60
      hash1 = "1831806fc27d496f0f9dcfd8402724189deaeb5f8bcf0118f3d6484d0bdee9ed"
      id = "08ffb61a-e2de-538e-9d9f-040276324af9"
   strings:
      $x2 = "\\Ammyy\\sources\\main\\Downloader.cpp" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}