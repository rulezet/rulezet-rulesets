rule TTP_XOR_WriteProcessMemory_618c {
  strings:
    $key_618c = { 36 fe [2] 04 dc [2] 02 e9 [2] 2c e9 [2] 13 f5 }

  condition:
    any of them
}