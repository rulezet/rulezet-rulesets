rule TTP_XOR_WriteProcessMemory_6bb0 {
  strings:
    $key_6bb0 = { 3c c2 [2] 0e e0 [2] 08 d5 [2] 26 d5 [2] 19 c9 }

  condition:
    any of them
}