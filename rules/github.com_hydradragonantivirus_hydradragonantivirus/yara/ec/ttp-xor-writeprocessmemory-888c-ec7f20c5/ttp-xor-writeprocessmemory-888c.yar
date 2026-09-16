rule TTP_XOR_WriteProcessMemory_888c {
  strings:
    $key_888c = { df fe [2] ed dc [2] eb e9 [2] c5 e9 [2] fa f5 }

  condition:
    any of them
}