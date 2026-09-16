rule TTP_XOR_WriteProcessMemory_b2a6 {
  strings:
    $key_b2a6 = { e5 d4 [2] d7 f6 [2] d1 c3 [2] ff c3 [2] c0 df }

  condition:
    any of them
}