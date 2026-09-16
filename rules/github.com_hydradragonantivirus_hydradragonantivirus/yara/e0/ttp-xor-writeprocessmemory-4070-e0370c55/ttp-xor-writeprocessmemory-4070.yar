rule TTP_XOR_WriteProcessMemory_4070 {
  strings:
    $key_4070 = { 17 02 [2] 25 20 [2] 23 15 [2] 0d 15 [2] 32 09 }

  condition:
    any of them
}