rule TTP_XOR_WriteProcessMemory_28b1 {
  strings:
    $key_28b1 = { 7f c3 [2] 4d e1 [2] 4b d4 [2] 65 d4 [2] 5a c8 }

  condition:
    any of them
}