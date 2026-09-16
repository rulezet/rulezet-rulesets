rule TTP_XOR_WriteProcessMemory_d232 {
  strings:
    $key_d232 = { 85 40 [2] b7 62 [2] b1 57 [2] 9f 57 [2] a0 4b }

  condition:
    any of them
}