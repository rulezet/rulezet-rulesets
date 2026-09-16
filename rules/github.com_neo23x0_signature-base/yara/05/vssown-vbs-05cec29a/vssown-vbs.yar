rule VSSown_VBS {
   meta:
      description = "Detects VSSown.vbs script - used to export shadow copy elements like NTDS to take away and crack elsewhere"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "2015-10-01"
      score = 75
      id = "ffbb5faf-3522-50dc-a568-503074ac0636"
   strings:
      $s0 = "Select * from Win32_Service Where Name ='VSS'" ascii
      $s1 = "Select * From Win32_ShadowCopy" ascii
      $s2 = "cmd /C mklink /D " ascii
      $s3 = "ClientAccessible" ascii
      $s4 = "WScript.Shell" ascii
      $s5 = "Win32_Process" ascii
   condition:
      all of them
}