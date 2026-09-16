rule iKAT_revelations {
   meta:
      description = "iKAT hack tool showing the content of password fields - file revelations.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "05.11.14"
      score = 75
      reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
      hash = "c4e217a8f2a2433297961561c5926cbd522f7996"
      id = "c5ef2c2a-c9c0-5c3a-bbcc-0b0949527850"
   strings:
      $s0 = "The RevelationHelper.DLL file is corrupt or missing." fullword ascii
      $s8 = "BETAsupport@snadboy.com" fullword wide
      $s9 = "support@snadboy.com" fullword wide
      $s14 = "RevelationHelper.dll" fullword ascii
   condition:
      all of them
}