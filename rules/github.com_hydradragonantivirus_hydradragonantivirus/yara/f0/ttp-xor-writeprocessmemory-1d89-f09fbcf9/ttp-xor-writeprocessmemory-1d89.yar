rule TTP_XOR_WriteProcessMemory_1d89 {
  strings:
    $key_1d89 = { 4a fb [2] 78 d9 [2] 7e ec [2] 50 ec [2] 6f f0 }

  condition:
    any of them
}