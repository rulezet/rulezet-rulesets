rule TTP_XOR_WriteProcessMemory_da40 {
  strings:
    $key_da40 = { 8d 32 [2] bf 10 [2] b9 25 [2] 97 25 [2] a8 39 }

  condition:
    any of them
}