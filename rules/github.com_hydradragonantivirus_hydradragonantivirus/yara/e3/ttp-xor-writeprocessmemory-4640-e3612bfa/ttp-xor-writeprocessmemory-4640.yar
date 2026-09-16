rule TTP_XOR_WriteProcessMemory_4640 {
  strings:
    $key_4640 = { 11 32 [2] 23 10 [2] 25 25 [2] 0b 25 [2] 34 39 }

  condition:
    any of them
}