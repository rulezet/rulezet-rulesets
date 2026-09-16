rule TTP_XOR_WriteProcessMemory_c789 {
  strings:
    $key_c789 = { 90 fb [2] a2 d9 [2] a4 ec [2] 8a ec [2] b5 f0 }

  condition:
    any of them
}