rule TTP_XOR_WriteProcessMemory_d6f7 {
  strings:
    $key_d6f7 = { 81 85 [2] b3 a7 [2] b5 92 [2] 9b 92 [2] a4 8e }

  condition:
    any of them
}