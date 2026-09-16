rule TTP_XOR_WriteProcessMemory_2a70 {
  strings:
    $key_2a70 = { 7d 02 [2] 4f 20 [2] 49 15 [2] 67 15 [2] 58 09 }

  condition:
    any of them
}