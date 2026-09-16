rule TTP_XOR_WriteProcessMemory_30e9 {
  strings:
    $key_30e9 = { 67 9b [2] 55 b9 [2] 53 8c [2] 7d 8c [2] 42 90 }

  condition:
    any of them
}