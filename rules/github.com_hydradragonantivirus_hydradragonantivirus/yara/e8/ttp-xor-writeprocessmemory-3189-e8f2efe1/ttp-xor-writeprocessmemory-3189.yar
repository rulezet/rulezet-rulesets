rule TTP_XOR_WriteProcessMemory_3189 {
  strings:
    $key_3189 = { 66 fb [2] 54 d9 [2] 52 ec [2] 7c ec [2] 43 f0 }

  condition:
    any of them
}