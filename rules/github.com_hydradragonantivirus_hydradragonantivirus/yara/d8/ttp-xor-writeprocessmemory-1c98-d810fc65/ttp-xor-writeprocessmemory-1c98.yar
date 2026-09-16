rule TTP_XOR_WriteProcessMemory_1c98 {
  strings:
    $key_1c98 = { 4b ea [2] 79 c8 [2] 7f fd [2] 51 fd [2] 6e e1 }

  condition:
    any of them
}