rule TTP_XOR_WriteProcessMemory_5b89 {
  strings:
    $key_5b89 = { 0c fb [2] 3e d9 [2] 38 ec [2] 16 ec [2] 29 f0 }

  condition:
    any of them
}