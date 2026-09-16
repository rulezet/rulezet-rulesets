rule TTP_XOR_WriteProcessMemory_6c98 {
  strings:
    $key_6c98 = { 3b ea [2] 09 c8 [2] 0f fd [2] 21 fd [2] 1e e1 }

  condition:
    any of them
}