rule TTP_XOR_WriteProcessMemory_ea89 {
  strings:
    $key_ea89 = { bd fb [2] 8f d9 [2] 89 ec [2] a7 ec [2] 98 f0 }

  condition:
    any of them
}