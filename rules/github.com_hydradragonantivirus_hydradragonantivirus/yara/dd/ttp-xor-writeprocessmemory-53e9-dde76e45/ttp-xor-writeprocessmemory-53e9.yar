rule TTP_XOR_WriteProcessMemory_53e9 {
  strings:
    $key_53e9 = { 04 9b [2] 36 b9 [2] 30 8c [2] 1e 8c [2] 21 90 }

  condition:
    any of them
}