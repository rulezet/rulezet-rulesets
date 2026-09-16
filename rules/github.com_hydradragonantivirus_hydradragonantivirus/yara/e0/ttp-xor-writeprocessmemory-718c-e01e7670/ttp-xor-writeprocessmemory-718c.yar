rule TTP_XOR_WriteProcessMemory_718c {
  strings:
    $key_718c = { 26 fe [2] 14 dc [2] 12 e9 [2] 3c e9 [2] 03 f5 }

  condition:
    any of them
}