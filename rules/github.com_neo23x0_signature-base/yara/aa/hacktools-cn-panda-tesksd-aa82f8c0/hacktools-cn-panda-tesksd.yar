rule Hacktools_CN_Panda_tesksd {
   meta:
      description = "Disclosed hacktool set - file tesksd.jpg"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "17.11.14"
      score = 60
      hash = "922147b3e1e6cf1f5dd5f64a4e34d28bdc9128cb"
      id = "399ff307-c2e8-57bb-b792-a2c599e8686e"
   strings:
      $s0 = "name=\"Microsoft.Windows.Common-Controls\" " fullword ascii
      $s1 = "ExeMiniDownload.exe" fullword wide
      $s16 = "POST %Hs" fullword ascii
   condition:
      all of them
}