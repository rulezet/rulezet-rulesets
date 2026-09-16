rule TTP_XOR_WriteProcessMemory_4e89 {
  strings:
    $key_4e89 = { 19 fb [2] 2b d9 [2] 2d ec [2] 03 ec [2] 3c f0 }

  condition:
    any of them
}