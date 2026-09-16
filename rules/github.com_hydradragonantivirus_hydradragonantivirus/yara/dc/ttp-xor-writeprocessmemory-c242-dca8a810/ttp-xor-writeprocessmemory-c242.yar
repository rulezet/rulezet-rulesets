rule TTP_XOR_WriteProcessMemory_c242 {
  strings:
    $key_c242 = { 95 30 [2] a7 12 [2] a1 27 [2] 8f 27 [2] b0 3b }

  condition:
    any of them
}