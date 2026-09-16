rule TTP_XOR_WriteProcessMemory_6519 {
  strings:
    $key_6519 = { 32 6b [2] 00 49 [2] 06 7c [2] 28 7c [2] 17 60 }

  condition:
    any of them
}