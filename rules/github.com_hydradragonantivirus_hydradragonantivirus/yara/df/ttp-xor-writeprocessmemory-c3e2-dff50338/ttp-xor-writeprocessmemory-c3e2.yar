rule TTP_XOR_WriteProcessMemory_c3e2 {
  strings:
    $key_c3e2 = { 94 90 [2] a6 b2 [2] a0 87 [2] 8e 87 [2] b1 9b }

  condition:
    any of them
}