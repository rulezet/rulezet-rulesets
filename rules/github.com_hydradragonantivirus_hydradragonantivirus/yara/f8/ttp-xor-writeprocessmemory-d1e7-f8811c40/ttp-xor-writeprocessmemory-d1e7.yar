rule TTP_XOR_WriteProcessMemory_d1e7 {
  strings:
    $key_d1e7 = { 86 95 [2] b4 b7 [2] b2 82 [2] 9c 82 [2] a3 9e }

  condition:
    any of them
}