rule Certutil_Decode_OR_Download {
   meta:
      description = "Certutil Decode"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      score = 40
      date = "2017-08-29"
      modified = "2023-10-19"
      id = "63bdefd2-225a-56d5-b615-5e236c97f050"
   strings:
      $a1 = "certutil -decode " ascii wide
      $a2 = "certutil  -decode " ascii wide
      $a3 = "certutil.exe -decode " ascii wide
      $a4 = "certutil.exe  -decode " ascii wide
      $a5 = "certutil -urlcache -split -f http" ascii wide
      $a6 = "certutil.exe -urlcache -split -f http" ascii wide

      $fp_msi = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 }
   condition:
      filesize < 700KB
      and 1 of ($a*)
      and not 1 of ($fp*)
}