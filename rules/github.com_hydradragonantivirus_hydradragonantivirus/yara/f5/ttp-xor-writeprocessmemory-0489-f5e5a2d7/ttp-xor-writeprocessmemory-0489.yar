rule TTP_XOR_WriteProcessMemory_0489 {
  strings:
    $key_0489 = { 53 fb [2] 61 d9 [2] 67 ec [2] 49 ec [2] 76 f0 }

  condition:
    any of them
}