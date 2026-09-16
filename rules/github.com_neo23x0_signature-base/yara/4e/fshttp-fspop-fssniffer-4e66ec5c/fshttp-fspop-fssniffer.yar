rule _FsHttp_FsPop_FsSniffer {
   meta:
      description = "Disclosed hacktool set (old stuff) - from files FsHttp.exe, FsPop.exe, FsSniffer.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      super_rule = 1
      hash0 = "9d4e7611a328eb430a8bb6dc7832440713926f5f"
      hash1 = "ae23522a3529d3313dd883727c341331a1fb1ab9"
      hash2 = "7ffc496cd4a1017485dfb571329523a52c9032d8"
      id = "5ca543af-2589-52b0-83f9-ad25ba76b633"
   strings:
      $s0 = "-ERR Invalid Command, Type [Help] For Command List" fullword
      $s1 = "-ERR Get SMS Users ID Failed" fullword
      $s2 = "Control Time Out 90 Secs, Connection Closed" fullword
      $s3 = "-ERR Post SMS Failed" fullword
      $s4 = "Current.hlt" fullword
      $s6 = "Histroy.hlt" fullword
      $s7 = "-ERR Send SMS Failed" fullword
      $s12 = "-ERR Change Password <New Password>" fullword
      $s17 = "+OK Send SMS Succussifully" fullword
      $s18 = "+OK Set New Password: [%s]" fullword
      $s19 = "CHANGE PASSWORD" fullword
   condition:
      all of them
}