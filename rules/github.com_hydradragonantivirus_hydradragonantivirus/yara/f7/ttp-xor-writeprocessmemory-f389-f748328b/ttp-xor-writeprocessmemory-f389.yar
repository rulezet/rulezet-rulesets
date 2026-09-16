rule TTP_XOR_WriteProcessMemory_f389 {
  strings:
    $key_f389 = { a4 fb [2] 96 d9 [2] 90 ec [2] be ec [2] 81 f0 }

  condition:
    any of them
}