rule TTP_XOR_WriteProcessMemory_7b89 {
  strings:
    $key_7b89 = { 2c fb [2] 1e d9 [2] 18 ec [2] 36 ec [2] 09 f0 }

  condition:
    any of them
}