rule TTP_XOR_WriteProcessMemory_3de2 {
  strings:
    $key_3de2 = { 6a 90 [2] 58 b2 [2] 5e 87 [2] 70 87 [2] 4f 9b }

  condition:
    any of them
}