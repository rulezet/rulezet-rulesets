rule TTP_XOR_WriteProcessMemory_d1d1 {
  strings:
    $key_d1d1 = { 86 a3 [2] b4 81 [2] b2 b4 [2] 9c b4 [2] a3 a8 }

  condition:
    any of them
}