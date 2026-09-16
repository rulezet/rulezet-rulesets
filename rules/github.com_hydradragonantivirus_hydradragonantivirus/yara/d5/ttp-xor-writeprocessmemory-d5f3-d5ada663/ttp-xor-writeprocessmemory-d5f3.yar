rule TTP_XOR_WriteProcessMemory_d5f3 {
  strings:
    $key_d5f3 = { 82 81 [2] b0 a3 [2] b6 96 [2] 98 96 [2] a7 8a }

  condition:
    any of them
}