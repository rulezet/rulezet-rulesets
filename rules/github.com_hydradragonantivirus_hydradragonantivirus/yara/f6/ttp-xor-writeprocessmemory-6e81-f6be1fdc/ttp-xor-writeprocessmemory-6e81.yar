rule TTP_XOR_WriteProcessMemory_6e81 {
  strings:
    $key_6e81 = { 39 f3 [2] 0b d1 [2] 0d e4 [2] 23 e4 [2] 1c f8 }

  condition:
    any of them
}