rule TTP_XOR_WriteProcessMemory_d1c1 {
  strings:
    $key_d1c1 = { 86 b3 [2] b4 91 [2] b2 a4 [2] 9c a4 [2] a3 b8 }

  condition:
    any of them
}