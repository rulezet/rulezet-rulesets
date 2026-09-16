rule TTP_XOR_WriteProcessMemory_1ff9 {
  strings:
    $key_1ff9 = { 48 8b [2] 7a a9 [2] 7c 9c [2] 52 9c [2] 6d 80 }

  condition:
    any of them
}