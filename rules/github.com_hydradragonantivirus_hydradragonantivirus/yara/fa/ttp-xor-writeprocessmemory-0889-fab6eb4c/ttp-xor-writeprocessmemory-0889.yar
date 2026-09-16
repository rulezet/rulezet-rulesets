rule TTP_XOR_WriteProcessMemory_0889 {
  strings:
    $key_0889 = { 5f fb [2] 6d d9 [2] 6b ec [2] 45 ec [2] 7a f0 }

  condition:
    any of them
}