rule ReactOS_cmd_valid {
   meta:
      description = "ReactOS cmd.exe with correct file name - maybe packed with software or part of hacker toolset"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "05.11.14"
      reference = "http://www.elifulkerson.com/articles/suzy-sells-cmd-shells.php"
      score = 30
      hash = "b88f050fa69d85af3ff99af90a157435296cbb6e"
      id = "47df12b4-d202-5520-9c7f-9d0196bc2267"
   strings:
      $s1 = "ReactOS Command Processor" fullword wide
      $s2 = "Copyright (C) 1994-1998 Tim Norman and others" fullword wide
      $s3 = "Eric Kohl and others" fullword wide
      $s4 = "ReactOS Operating System" fullword wide
   condition:
      all of ($s*)
}