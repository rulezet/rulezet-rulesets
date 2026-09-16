rule TTP_XOR_WriteProcessMemory_c389 {
  strings:
    $key_c389 = { 94 fb [2] a6 d9 [2] a0 ec [2] 8e ec [2] b1 f0 }

  condition:
    any of them
}