rule TTP_XOR_WriteProcessMemory_da02 {
  strings:
    $key_da02 = { 8d 70 [2] bf 52 [2] b9 67 [2] 97 67 [2] a8 7b }

  condition:
    any of them
}