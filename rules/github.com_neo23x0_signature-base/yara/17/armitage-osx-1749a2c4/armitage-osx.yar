rule Armitage_OSX {
   meta:
      description = "Detects Armitage component"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-12-24"
      hash1 = "2680d9900a057d553fcb28d84cdc41c3fc18fd224a88a32ee14c9c1b501a86af"
      hash2 = "b7b506f38d0553cd2beb4111c7ef383c821f04cee5169fed2ef5d869c9fbfab3"
      id = "e886e866-c163-56fb-9631-c586e9f23f9e"
   strings:
      $x1 = "resources/covertvpn-injector.exe" fullword ascii
      $s10 = "resources/browserpivot.x64.dll" fullword ascii
      $s17 = "resources/msfrpcd_new.bat" fullword ascii
   condition:
      filesize < 6000KB and 1 of them
}