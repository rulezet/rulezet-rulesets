rule TTP_XOR_WriteProcessMemory_1cf9 {
  strings:
    $key_1cf9 = { 4b 8b [2] 79 a9 [2] 7f 9c [2] 51 9c [2] 6e 80 }

  condition:
    any of them
}