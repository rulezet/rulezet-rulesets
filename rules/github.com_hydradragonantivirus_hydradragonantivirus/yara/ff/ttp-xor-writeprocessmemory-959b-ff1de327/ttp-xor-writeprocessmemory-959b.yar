rule TTP_XOR_WriteProcessMemory_959b {
  strings:
    $key_959b = { c2 e9 [2] f0 cb [2] f6 fe [2] d8 fe [2] e7 e2 }

  condition:
    any of them
}