rule CN_Toolset_NTscan_PipeCmd {
   meta:
      description = "Detects a Chinese hacktool from a disclosed toolset - file PipeCmd.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://qiannao.com/ls/905300366/33834c0c/"
      date = "2015/03/30"
      score = 70
      hash = "a931d65de66e1468fe2362f7f2e0ee546f225c4e"
      id = "056ee42d-23f4-5b03-b240-392bc92b90b0"
   strings:
      $s2 = "Please Use NTCmd.exe Run This Program." fullword ascii
      $s3 = "PipeCmd.exe" fullword wide
      $s4 = "\\\\.\\pipe\\%s%s%d" fullword ascii
      $s5 = "%s\\pipe\\%s%s%d" fullword ascii
      $s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
      $s7 = "%s\\ADMIN$\\System32\\%s" fullword ascii
      $s9 = "PipeCmdSrv.exe" fullword ascii
      $s10 = "This is a service executable! Couldn't start directly." fullword ascii
      $s13 = "\\\\.\\pipe\\PipeCmd_communicaton" fullword ascii
      $s14 = "PIPECMDSRV" fullword wide
      $s15 = "PipeCmd Service" fullword ascii
   condition:
      4 of them
}