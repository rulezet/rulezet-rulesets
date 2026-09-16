rule TTP_XOR_WriteProcessMemory_da22 {
  strings:
    $key_da22 = { 8d 50 [2] bf 72 [2] b9 47 [2] 97 47 [2] a8 5b }

  condition:
    any of them
}