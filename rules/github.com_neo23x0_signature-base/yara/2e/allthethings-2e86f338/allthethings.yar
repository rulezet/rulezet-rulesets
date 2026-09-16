rule AllTheThings {
   meta:
      description = "Detects AllTheThings"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/subTee/AllTheThings"
      date = "2017-07-27"
      modified = "2022-12-21"
      hash1 = "5a0e9a9ce00d843ea95bd5333b6ab50cc5b1dbea648cc819cfe48482513ce842"
      id = "c3169ca7-3482-5d55-a1d9-6d1c01349922"
   strings:
      $x1 = "\\obj\\Debug\\AllTheThings.pdb" ascii
      $x2 = "AllTheThings.exe" fullword wide
      $x3 = "\\AllTheThings.dll" ascii
      $x4 = "Hello From Main...I Don't Do Anything" fullword wide
      $x5 = "I am a basic COM Object" fullword wide
      $x6 = "I shouldn't really execute either." fullword wide
   condition:
      (uint16(0) == 0x5a4d and filesize < 50KB and 1 of them)
}