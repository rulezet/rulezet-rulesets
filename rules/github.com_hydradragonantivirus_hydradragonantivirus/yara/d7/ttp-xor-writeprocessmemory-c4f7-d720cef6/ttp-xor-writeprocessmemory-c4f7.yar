rule TTP_XOR_WriteProcessMemory_c4f7 {
  strings:
    $key_c4f7 = { 93 85 [2] a1 a7 [2] a7 92 [2] 89 92 [2] b6 8e }

  condition:
    any of them
}