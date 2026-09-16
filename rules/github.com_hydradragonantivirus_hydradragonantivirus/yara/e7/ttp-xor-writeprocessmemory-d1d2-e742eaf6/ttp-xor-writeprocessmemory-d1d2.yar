rule TTP_XOR_WriteProcessMemory_d1d2 {
  strings:
    $key_d1d2 = { 86 a0 [2] b4 82 [2] b2 b7 [2] 9c b7 [2] a3 ab }

  condition:
    any of them
}