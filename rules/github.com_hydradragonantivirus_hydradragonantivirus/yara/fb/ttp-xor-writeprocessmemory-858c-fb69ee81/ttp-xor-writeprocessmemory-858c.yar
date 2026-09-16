rule TTP_XOR_WriteProcessMemory_858c {
  strings:
    $key_858c = { d2 fe [2] e0 dc [2] e6 e9 [2] c8 e9 [2] f7 f5 }

  condition:
    any of them
}