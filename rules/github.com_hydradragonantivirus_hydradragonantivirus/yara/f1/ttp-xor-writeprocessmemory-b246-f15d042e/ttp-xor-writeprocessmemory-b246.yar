rule TTP_XOR_WriteProcessMemory_b246 {
  strings:
    $key_b246 = { e5 34 [2] d7 16 [2] d1 23 [2] ff 23 [2] c0 3f }

  condition:
    any of them
}