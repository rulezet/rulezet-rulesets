rule TTP_XOR_WriteProcessMemory_d791 {
  strings:
    $key_d791 = { 80 e3 [2] b2 c1 [2] b4 f4 [2] 9a f4 [2] a5 e8 }

  condition:
    any of them
}