rule TTP_XOR_WriteProcessMemory_fe89 {
  strings:
    $key_fe89 = { a9 fb [2] 9b d9 [2] 9d ec [2] b3 ec [2] 8c f0 }

  condition:
    any of them
}