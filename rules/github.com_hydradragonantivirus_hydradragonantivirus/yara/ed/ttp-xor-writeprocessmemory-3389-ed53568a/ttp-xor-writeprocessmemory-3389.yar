rule TTP_XOR_WriteProcessMemory_3389 {
  strings:
    $key_3389 = { 64 fb [2] 56 d9 [2] 50 ec [2] 7e ec [2] 41 f0 }

  condition:
    any of them
}