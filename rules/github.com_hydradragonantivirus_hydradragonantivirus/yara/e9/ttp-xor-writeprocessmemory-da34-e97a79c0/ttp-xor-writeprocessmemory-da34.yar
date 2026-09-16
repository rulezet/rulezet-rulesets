rule TTP_XOR_WriteProcessMemory_da34 {
  strings:
    $key_da34 = { 8d 46 [2] bf 64 [2] b9 51 [2] 97 51 [2] a8 4d }

  condition:
    any of them
}