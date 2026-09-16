rule TTP_XOR_WriteProcessMemory_0b89 {
  strings:
    $key_0b89 = { 5c fb [2] 6e d9 [2] 68 ec [2] 46 ec [2] 79 f0 }

  condition:
    any of them
}