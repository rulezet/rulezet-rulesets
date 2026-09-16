rule info_macos_scpt_applet {
  meta:
    description = "Identify macOS AppleScript Applet stubs."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.04.06"
    DaysofYARA  = "96/100"

  strings:
    $s0 = "_OpenDefaultComponent"
    $s1 = "_CallComponentDispatch"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    all of them
}