rule TTP_XOR_WriteProcessMemory_e789 {
  strings:
    $key_e789 = { b0 fb [2] 82 d9 [2] 84 ec [2] aa ec [2] 95 f0 }

  condition:
    any of them
}