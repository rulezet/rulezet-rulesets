rule TTP_XOR_WriteProcessMemory_c489 {
  strings:
    $key_c489 = { 93 fb [2] a1 d9 [2] a7 ec [2] 89 ec [2] b6 f0 }

  condition:
    any of them
}