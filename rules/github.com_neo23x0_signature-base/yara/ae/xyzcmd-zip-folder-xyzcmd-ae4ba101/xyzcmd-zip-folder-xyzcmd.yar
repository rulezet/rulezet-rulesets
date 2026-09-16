rule XYZCmd_zip_Folder_XYZCmd {
   meta:
      description = "Disclosed hacktool set (old stuff) - file XYZCmd.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "bbea5a94950b0e8aab4a12ad80e09b630dd98115"
      id = "c3d70b93-1d53-5403-bd22-d1e4bad5042b"
   strings:
      $s0 = "Executes Command Remotely" fullword wide
      $s2 = "XYZCmd.exe" fullword wide
      $s6 = "No Client Software" fullword wide
      $s19 = "XYZCmd V1.0 For NT S" fullword ascii
   condition:
      all of them
}