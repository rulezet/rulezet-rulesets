rule TTP_XOR_WriteProcessMemory_1519 {
  strings:
    $key_1519 = { 42 6b [2] 70 49 [2] 76 7c [2] 58 7c [2] 67 60 }

  condition:
    any of them
}