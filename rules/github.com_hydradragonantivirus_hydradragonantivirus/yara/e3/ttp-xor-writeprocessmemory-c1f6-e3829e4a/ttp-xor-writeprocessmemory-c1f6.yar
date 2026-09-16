rule TTP_XOR_WriteProcessMemory_c1f6 {
  strings:
    $key_c1f6 = { 96 84 [2] a4 a6 [2] a2 93 [2] 8c 93 [2] b3 8f }

  condition:
    any of them
}