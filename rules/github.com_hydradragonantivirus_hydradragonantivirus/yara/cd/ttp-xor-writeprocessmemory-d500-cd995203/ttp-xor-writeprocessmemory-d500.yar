rule TTP_XOR_WriteProcessMemory_d500 {
  strings:
    $key_d500 = { 82 72 [2] b0 50 [2] b6 65 [2] 98 65 [2] a7 79 }

  condition:
    any of them
}