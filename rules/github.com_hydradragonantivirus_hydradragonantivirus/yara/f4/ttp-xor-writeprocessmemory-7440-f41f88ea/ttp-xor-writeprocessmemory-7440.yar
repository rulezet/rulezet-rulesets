rule TTP_XOR_WriteProcessMemory_7440 {
  strings:
    $key_7440 = { 23 32 [2] 11 10 [2] 17 25 [2] 39 25 [2] 06 39 }

  condition:
    any of them
}