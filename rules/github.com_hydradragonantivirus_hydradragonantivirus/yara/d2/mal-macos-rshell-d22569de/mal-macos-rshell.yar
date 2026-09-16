rule mal_macos_rshell {
  meta:
    description = "Identify macOS rshell backdoor."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.19"
    sample      = "3a9e72b3810b320fa6826a1273732fee7a8e2b2e5c0fd95b8c36bbab970e830a"
    DaysofYARA  = "78/100"

  strings:
    $s0 = "/proc/self/exe"
    $s1 = "/tmp/guid"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    all of them
}