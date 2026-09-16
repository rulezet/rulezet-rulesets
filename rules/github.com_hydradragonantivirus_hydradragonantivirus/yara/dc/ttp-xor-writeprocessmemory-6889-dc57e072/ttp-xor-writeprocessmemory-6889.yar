rule TTP_XOR_WriteProcessMemory_6889 {
  strings:
    $key_6889 = { 3f fb [2] 0d d9 [2] 0b ec [2] 25 ec [2] 1a f0 }

  condition:
    any of them
}