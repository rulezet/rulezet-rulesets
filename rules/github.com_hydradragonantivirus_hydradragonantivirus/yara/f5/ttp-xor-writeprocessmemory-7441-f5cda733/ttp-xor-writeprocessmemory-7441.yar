rule TTP_XOR_WriteProcessMemory_7441 {
  strings:
    $key_7441 = { 23 33 [2] 11 11 [2] 17 24 [2] 39 24 [2] 06 38 }

  condition:
    any of them
}