rule TTP_XOR_WriteProcessMemory_da26 {
  strings:
    $key_da26 = { 8d 54 [2] bf 76 [2] b9 43 [2] 97 43 [2] a8 5f }

  condition:
    any of them
}