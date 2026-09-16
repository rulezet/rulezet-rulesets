rule TTP_XOR_WriteProcessMemory_25e9 {
  strings:
    $key_25e9 = { 72 9b [2] 40 b9 [2] 46 8c [2] 68 8c [2] 57 90 }

  condition:
    any of them
}