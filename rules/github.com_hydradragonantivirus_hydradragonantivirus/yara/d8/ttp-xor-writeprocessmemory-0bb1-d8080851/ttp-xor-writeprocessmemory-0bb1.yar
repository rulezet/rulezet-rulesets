rule TTP_XOR_WriteProcessMemory_0bb1 {
  strings:
    $key_0bb1 = { 5c c3 [2] 6e e1 [2] 68 d4 [2] 46 d4 [2] 79 c8 }

  condition:
    any of them
}