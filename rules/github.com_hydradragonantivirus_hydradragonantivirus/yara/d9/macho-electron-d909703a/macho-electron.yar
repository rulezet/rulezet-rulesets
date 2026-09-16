rule macho_electron {
  meta:
    description = "Identify Electron based executables. Stub Macho that loads JS."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.02.03"
    reference   = "https://github.com/electron/electron"
    DaysofYARA  = "34/100"

  strings:
    $s1 = "ELECTRON_RUN_AS_NODE"
    $s2 = "Electron Framework.framework"
    $s3 = "_ElectronMain"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    all of them
}