rule TTP_XOR_WriteProcessMemory_a589 {
  strings:
    $key_a589 = { f2 fb [2] c0 d9 [2] c6 ec [2] e8 ec [2] d7 f0 }

  condition:
    any of them
}