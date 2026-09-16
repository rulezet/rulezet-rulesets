rule TTP_XOR_WriteProcessMemory_c442 {
  strings:
    $key_c442 = { 93 30 [2] a1 12 [2] a7 27 [2] 89 27 [2] b6 3b }

  condition:
    any of them
}