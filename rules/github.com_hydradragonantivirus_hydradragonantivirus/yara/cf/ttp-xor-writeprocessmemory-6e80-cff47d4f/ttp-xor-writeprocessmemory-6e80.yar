rule TTP_XOR_WriteProcessMemory_6e80 {
  strings:
    $key_6e80 = { 39 f2 [2] 0b d0 [2] 0d e5 [2] 23 e5 [2] 1c f9 }

  condition:
    any of them
}