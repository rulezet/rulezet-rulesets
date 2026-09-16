rule TTP_XOR_WriteProcessMemory_a089 {
  strings:
    $key_a089 = { f7 fb [2] c5 d9 [2] c3 ec [2] ed ec [2] d2 f0 }

  condition:
    any of them
}