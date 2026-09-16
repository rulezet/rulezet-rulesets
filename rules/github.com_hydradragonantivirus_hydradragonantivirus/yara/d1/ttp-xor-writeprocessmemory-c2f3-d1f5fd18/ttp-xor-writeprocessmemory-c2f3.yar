rule TTP_XOR_WriteProcessMemory_c2f3 {
  strings:
    $key_c2f3 = { 95 81 [2] a7 a3 [2] a1 96 [2] 8f 96 [2] b0 8a }

  condition:
    any of them
}