rule TTP_XOR_WriteProcessMemory_d300 {
  strings:
    $key_d300 = { 84 72 [2] b6 50 [2] b0 65 [2] 9e 65 [2] a1 79 }

  condition:
    any of them
}