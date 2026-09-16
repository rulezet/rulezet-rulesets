rule TTP_XOR_WriteProcessMemory_7889 {
  strings:
    $key_7889 = { 2f fb [2] 1d d9 [2] 1b ec [2] 35 ec [2] 0a f0 }

  condition:
    any of them
}