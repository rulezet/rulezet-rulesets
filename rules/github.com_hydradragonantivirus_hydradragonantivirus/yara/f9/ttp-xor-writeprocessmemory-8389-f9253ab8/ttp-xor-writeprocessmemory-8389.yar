rule TTP_XOR_WriteProcessMemory_8389 {
  strings:
    $key_8389 = { d4 fb [2] e6 d9 [2] e0 ec [2] ce ec [2] f1 f0 }

  condition:
    any of them
}