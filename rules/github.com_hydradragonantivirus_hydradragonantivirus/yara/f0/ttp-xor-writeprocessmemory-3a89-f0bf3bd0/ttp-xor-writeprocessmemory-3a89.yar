rule TTP_XOR_WriteProcessMemory_3a89 {
  strings:
    $key_3a89 = { 6d fb [2] 5f d9 [2] 59 ec [2] 77 ec [2] 48 f0 }

  condition:
    any of them
}