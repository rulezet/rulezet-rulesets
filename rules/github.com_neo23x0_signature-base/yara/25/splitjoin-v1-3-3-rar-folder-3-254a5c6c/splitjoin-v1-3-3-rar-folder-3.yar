rule SplitJoin_V1_3_3_rar_Folder_3 {
   meta:
      description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "21409117b536664a913dcd159d6f4d8758f43435"
      id = "4ffd7501-339c-52b7-8661-2c3ca57dfa1f"
   strings:
      $s2 = "ie686@sohu.com" fullword ascii
      $s3 = "splitjoin.exe" fullword ascii
      $s7 = "SplitJoin" fullword ascii
   condition:
      all of them
}