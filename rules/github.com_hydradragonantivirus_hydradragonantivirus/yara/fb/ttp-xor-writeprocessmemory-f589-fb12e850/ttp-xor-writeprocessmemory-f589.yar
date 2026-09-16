rule TTP_XOR_WriteProcessMemory_f589 {
  strings:
    $key_f589 = { a2 fb [2] 90 d9 [2] 96 ec [2] b8 ec [2] 87 f0 }

  condition:
    any of them
}