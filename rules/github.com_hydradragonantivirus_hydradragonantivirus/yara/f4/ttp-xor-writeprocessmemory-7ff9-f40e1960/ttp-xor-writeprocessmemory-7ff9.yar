rule TTP_XOR_WriteProcessMemory_7ff9 {
  strings:
    $key_7ff9 = { 28 8b [2] 1a a9 [2] 1c 9c [2] 32 9c [2] 0d 80 }

  condition:
    any of them
}