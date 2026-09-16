rule TTP_XOR_WriteProcessMemory_7429 {
  strings:
    $key_7429 = { 23 5b [2] 11 79 [2] 17 4c [2] 39 4c [2] 06 50 }

  condition:
    any of them
}