rule TTP_XOR_WriteProcessMemory_4989 {
  strings:
    $key_4989 = { 1e fb [2] 2c d9 [2] 2a ec [2] 04 ec [2] 3b f0 }

  condition:
    any of them
}