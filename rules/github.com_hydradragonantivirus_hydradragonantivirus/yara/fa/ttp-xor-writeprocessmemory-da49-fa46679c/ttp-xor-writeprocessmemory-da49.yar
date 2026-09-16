rule TTP_XOR_WriteProcessMemory_da49 {
  strings:
    $key_da49 = { 8d 3b [2] bf 19 [2] b9 2c [2] 97 2c [2] a8 30 }

  condition:
    any of them
}