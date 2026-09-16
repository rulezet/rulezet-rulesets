rule WMI_vbs: APT {
   meta:
      description = "WMI Tool - APT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "2013-11-29"
      confidential = false
      score = 70
      id = "b367306a-38d8-5f4d-8f09-2bf025831f0a"
   strings:
      $s3 = "WScript.Echo \"   $$\\      $$\\ $$\\      $$\\ $$$$$$\\ $$$$$$$$\\ $$\\   $$\\ $$$$$$$$\\  $$$$$$"
   condition:
      all of them
}