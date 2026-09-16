rule TTP_XOR_WriteProcessMemory_2a52 {
  strings:
    $key_2a52 = { 7d 20 [2] 4f 02 [2] 49 37 [2] 67 37 [2] 58 2b }

  condition:
    any of them
}