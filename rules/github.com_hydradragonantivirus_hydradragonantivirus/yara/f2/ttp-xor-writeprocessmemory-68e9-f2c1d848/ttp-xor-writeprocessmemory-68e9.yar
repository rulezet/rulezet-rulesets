rule TTP_XOR_WriteProcessMemory_68e9 {
  strings:
    $key_68e9 = { 3f 9b [2] 0d b9 [2] 0b 8c [2] 25 8c [2] 1a 90 }

  condition:
    any of them
}