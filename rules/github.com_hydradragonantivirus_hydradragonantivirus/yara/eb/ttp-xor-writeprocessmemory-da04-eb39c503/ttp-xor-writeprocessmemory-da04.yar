rule TTP_XOR_WriteProcessMemory_da04 {
  strings:
    $key_da04 = { 8d 76 [2] bf 54 [2] b9 61 [2] 97 61 [2] a8 7d }

  condition:
    any of them
}