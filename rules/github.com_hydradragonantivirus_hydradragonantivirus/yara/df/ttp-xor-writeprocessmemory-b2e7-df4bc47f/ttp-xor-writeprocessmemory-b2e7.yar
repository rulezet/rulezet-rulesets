rule TTP_XOR_WriteProcessMemory_b2e7 {
  strings:
    $key_b2e7 = { e5 95 [2] d7 b7 [2] d1 82 [2] ff 82 [2] c0 9e }

  condition:
    any of them
}