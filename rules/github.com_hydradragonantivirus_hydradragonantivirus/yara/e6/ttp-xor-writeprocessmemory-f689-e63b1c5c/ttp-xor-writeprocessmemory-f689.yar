rule TTP_XOR_WriteProcessMemory_f689 {
  strings:
    $key_f689 = { a1 fb [2] 93 d9 [2] 95 ec [2] bb ec [2] 84 f0 }

  condition:
    any of them
}