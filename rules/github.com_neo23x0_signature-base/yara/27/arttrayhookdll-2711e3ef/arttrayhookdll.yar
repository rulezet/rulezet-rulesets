rule ArtTrayHookDll {
   meta:
      description = "Disclosed hacktool set (old stuff) - file ArtTrayHookDll.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "4867214a3d96095d14aa8575f0adbb81a9381e6c"
      id = "324561fc-024c-5583-aa25-6b13e9616898"
   strings:
      $s0 = "ArtTrayHookDll.dll" fullword ascii
      $s7 = "?TerminateHook@@YAXXZ" fullword ascii
   condition:
      all of them
}