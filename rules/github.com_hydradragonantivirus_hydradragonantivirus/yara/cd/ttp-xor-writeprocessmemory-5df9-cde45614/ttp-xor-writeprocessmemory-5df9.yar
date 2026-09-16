rule TTP_XOR_WriteProcessMemory_5df9 {
  strings:
    $key_5df9 = { 0a 8b [2] 38 a9 [2] 3e 9c [2] 10 9c [2] 2f 80 }

  condition:
    any of them
}