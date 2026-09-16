rule TTP_XOR_WriteProcessMemory_3489 {
  strings:
    $key_3489 = { 63 fb [2] 51 d9 [2] 57 ec [2] 79 ec [2] 46 f0 }

  condition:
    any of them
}