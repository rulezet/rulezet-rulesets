rule HKTL_Empire_PowerUp {
   meta:
      description = "Detects Empire component - file PowerUp.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "ad9a5dff257828ba5f15331d59dd4def3989537b3b6375495d0c08394460268c"
      id = "e79d093e-7481-52a3-a350-4d1b6d8955cd"
   strings:
      $x2 = "$PoolPasswordCmd = 'c:\\windows\\system32\\inetsrv\\appcmd.exe list apppool" fullword ascii
   condition:
      ( uint16(0) == 0x233c and filesize < 2000KB and 1 of them ) or all of them
}