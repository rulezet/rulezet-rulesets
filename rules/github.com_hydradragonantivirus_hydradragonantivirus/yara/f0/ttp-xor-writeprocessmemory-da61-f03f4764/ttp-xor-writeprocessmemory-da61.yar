rule TTP_XOR_WriteProcessMemory_da61 {
  strings:
    $key_da61 = { 8d 13 [2] bf 31 [2] b9 04 [2] 97 04 [2] a8 18 }

  condition:
    any of them
}