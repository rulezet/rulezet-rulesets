rule TTP_XOR_WriteProcessMemory_8489 {
  strings:
    $key_8489 = { d3 fb [2] e1 d9 [2] e7 ec [2] c9 ec [2] f6 f0 }

  condition:
    any of them
}