rule TTP_XOR_WriteProcessMemory_c2e7 {
  strings:
    $key_c2e7 = { 95 95 [2] a7 b7 [2] a1 82 [2] 8f 82 [2] b0 9e }

  condition:
    any of them
}