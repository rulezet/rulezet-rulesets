rule TTP_XOR_WriteProcessMemory_3a8c {
  strings:
    $key_3a8c = { 6d fe [2] 5f dc [2] 59 e9 [2] 77 e9 [2] 48 f5 }

  condition:
    any of them
}