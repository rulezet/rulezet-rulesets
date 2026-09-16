rule TTP_XOR_WriteProcessMemory_5889 {
  strings:
    $key_5889 = { 0f fb [2] 3d d9 [2] 3b ec [2] 15 ec [2] 2a f0 }

  condition:
    any of them
}