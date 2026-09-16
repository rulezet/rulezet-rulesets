rule TTP_XOR_WriteProcessMemory_6bb1 {
  strings:
    $key_6bb1 = { 3c c3 [2] 0e e1 [2] 08 d4 [2] 26 d4 [2] 19 c8 }

  condition:
    any of them
}