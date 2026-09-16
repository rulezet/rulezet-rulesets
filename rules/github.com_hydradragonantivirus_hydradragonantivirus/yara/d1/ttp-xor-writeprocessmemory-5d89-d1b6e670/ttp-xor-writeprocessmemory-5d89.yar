rule TTP_XOR_WriteProcessMemory_5d89 {
  strings:
    $key_5d89 = { 0a fb [2] 38 d9 [2] 3e ec [2] 10 ec [2] 2f f0 }

  condition:
    any of them
}