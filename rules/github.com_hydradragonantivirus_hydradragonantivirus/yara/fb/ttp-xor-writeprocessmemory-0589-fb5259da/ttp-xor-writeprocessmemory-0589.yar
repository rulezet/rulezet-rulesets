rule TTP_XOR_WriteProcessMemory_0589 {
  strings:
    $key_0589 = { 52 fb [2] 60 d9 [2] 66 ec [2] 48 ec [2] 77 f0 }

  condition:
    any of them
}