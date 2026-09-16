rule TTP_XOR_WriteProcessMemory_c140 {
  strings:
    $key_c140 = { 96 32 [2] a4 10 [2] a2 25 [2] 8c 25 [2] b3 39 }

  condition:
    any of them
}