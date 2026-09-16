rule TTP_XOR_WriteProcessMemory_ed9e {
  strings:
    $key_ed9e = { ba ec [2] 88 ce [2] 8e fb [2] a0 fb [2] 9f e7 }

  condition:
    any of them
}