rule TTP_XOR_WriteProcessMemory_c1d2 {
  strings:
    $key_c1d2 = { 96 a0 [2] a4 82 [2] a2 b7 [2] 8c b7 [2] b3 ab }

  condition:
    any of them
}