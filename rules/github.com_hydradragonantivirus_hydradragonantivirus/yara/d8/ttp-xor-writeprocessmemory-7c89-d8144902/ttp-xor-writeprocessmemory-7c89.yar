rule TTP_XOR_WriteProcessMemory_7c89 {
  strings:
    $key_7c89 = { 2b fb [2] 19 d9 [2] 1f ec [2] 31 ec [2] 0e f0 }

  condition:
    any of them
}