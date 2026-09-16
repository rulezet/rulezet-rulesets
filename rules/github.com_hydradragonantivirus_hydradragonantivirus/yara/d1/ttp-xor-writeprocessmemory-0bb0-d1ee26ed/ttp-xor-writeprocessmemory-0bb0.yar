rule TTP_XOR_WriteProcessMemory_0bb0 {
  strings:
    $key_0bb0 = { 5c c2 [2] 6e e0 [2] 68 d5 [2] 46 d5 [2] 79 c9 }

  condition:
    any of them
}