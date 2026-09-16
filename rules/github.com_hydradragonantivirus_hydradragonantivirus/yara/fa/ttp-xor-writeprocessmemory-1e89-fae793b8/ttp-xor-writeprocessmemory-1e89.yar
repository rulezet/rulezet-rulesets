rule TTP_XOR_WriteProcessMemory_1e89 {
  strings:
    $key_1e89 = { 49 fb [2] 7b d9 [2] 7d ec [2] 53 ec [2] 6c f0 }

  condition:
    any of them
}