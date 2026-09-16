rule TTP_XOR_WriteProcessMemory_4789 {
  strings:
    $key_4789 = { 10 fb [2] 22 d9 [2] 24 ec [2] 0a ec [2] 35 f0 }

  condition:
    any of them
}