rule TTP_XOR_WriteProcessMemory_4889 {
  strings:
    $key_4889 = { 1f fb [2] 2d d9 [2] 2b ec [2] 05 ec [2] 3a f0 }

  condition:
    any of them
}