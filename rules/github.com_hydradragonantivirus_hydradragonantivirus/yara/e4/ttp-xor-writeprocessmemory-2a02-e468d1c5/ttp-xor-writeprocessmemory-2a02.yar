rule TTP_XOR_WriteProcessMemory_2a02 {
  strings:
    $key_2a02 = { 7d 70 [2] 4f 52 [2] 49 67 [2] 67 67 [2] 58 7b }

  condition:
    any of them
}