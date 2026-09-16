rule TTP_XOR_WriteProcessMemory_da50 {
  strings:
    $key_da50 = { 8d 22 [2] bf 00 [2] b9 35 [2] 97 35 [2] a8 29 }

  condition:
    any of them
}