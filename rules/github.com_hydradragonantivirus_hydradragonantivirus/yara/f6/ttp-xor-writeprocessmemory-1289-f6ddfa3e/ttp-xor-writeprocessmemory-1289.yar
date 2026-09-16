rule TTP_XOR_WriteProcessMemory_1289 {
  strings:
    $key_1289 = { 45 fb [2] 77 d9 [2] 71 ec [2] 5f ec [2] 60 f0 }

  condition:
    any of them
}