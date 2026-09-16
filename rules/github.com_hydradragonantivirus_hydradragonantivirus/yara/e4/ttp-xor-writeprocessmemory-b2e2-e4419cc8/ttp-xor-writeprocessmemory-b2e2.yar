rule TTP_XOR_WriteProcessMemory_b2e2 {
  strings:
    $key_b2e2 = { e5 90 [2] d7 b2 [2] d1 87 [2] ff 87 [2] c0 9b }

  condition:
    any of them
}