rule TTP_XOR_WriteProcessMemory_45b1 {
  strings:
    $key_45b1 = { 12 c3 [2] 20 e1 [2] 26 d4 [2] 08 d4 [2] 37 c8 }

  condition:
    any of them
}