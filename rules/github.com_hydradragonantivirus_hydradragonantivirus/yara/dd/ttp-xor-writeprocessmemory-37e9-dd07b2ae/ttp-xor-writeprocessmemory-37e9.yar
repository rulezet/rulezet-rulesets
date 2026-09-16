rule TTP_XOR_WriteProcessMemory_37e9 {
  strings:
    $key_37e9 = { 60 9b [2] 52 b9 [2] 54 8c [2] 7a 8c [2] 45 90 }

  condition:
    any of them
}