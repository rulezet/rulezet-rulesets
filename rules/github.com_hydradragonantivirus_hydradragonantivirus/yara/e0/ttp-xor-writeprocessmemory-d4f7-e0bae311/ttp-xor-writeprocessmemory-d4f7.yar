rule TTP_XOR_WriteProcessMemory_d4f7 {
  strings:
    $key_d4f7 = { 83 85 [2] b1 a7 [2] b7 92 [2] 99 92 [2] a6 8e }

  condition:
    any of them
}