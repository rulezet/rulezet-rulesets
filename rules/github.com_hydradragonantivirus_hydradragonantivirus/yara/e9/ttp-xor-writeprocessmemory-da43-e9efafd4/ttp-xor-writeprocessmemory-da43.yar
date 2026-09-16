rule TTP_XOR_WriteProcessMemory_da43 {
  strings:
    $key_da43 = { 8d 31 [2] bf 13 [2] b9 26 [2] 97 26 [2] a8 3a }

  condition:
    any of them
}