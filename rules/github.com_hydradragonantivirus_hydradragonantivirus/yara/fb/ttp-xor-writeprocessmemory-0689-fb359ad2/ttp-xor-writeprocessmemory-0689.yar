rule TTP_XOR_WriteProcessMemory_0689 {
  strings:
    $key_0689 = { 51 fb [2] 63 d9 [2] 65 ec [2] 4b ec [2] 74 f0 }

  condition:
    any of them
}