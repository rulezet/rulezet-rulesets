rule TTP_XOR_WriteProcessMemory_ba9b {
  strings:
    $key_ba9b = { ed e9 [2] df cb [2] d9 fe [2] f7 fe [2] c8 e2 }

  condition:
    any of them
}