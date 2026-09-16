rule TTP_XOR_WriteProcessMemory_b281 {
  strings:
    $key_b281 = { e5 f3 [2] d7 d1 [2] d1 e4 [2] ff e4 [2] c0 f8 }

  condition:
    any of them
}