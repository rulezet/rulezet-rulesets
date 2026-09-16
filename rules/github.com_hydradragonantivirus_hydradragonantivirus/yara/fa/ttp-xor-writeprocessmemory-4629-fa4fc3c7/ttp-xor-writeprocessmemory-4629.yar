rule TTP_XOR_WriteProcessMemory_4629 {
  strings:
    $key_4629 = { 11 5b [2] 23 79 [2] 25 4c [2] 0b 4c [2] 34 50 }

  condition:
    any of them
}