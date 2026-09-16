rule TTP_XOR_WriteProcessMemory_c136 {
  strings:
    $key_c136 = { 96 44 [2] a4 66 [2] a2 53 [2] 8c 53 [2] b3 4f }

  condition:
    any of them
}