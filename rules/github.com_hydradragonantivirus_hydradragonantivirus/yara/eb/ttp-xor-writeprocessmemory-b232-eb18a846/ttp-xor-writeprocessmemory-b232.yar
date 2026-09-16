rule TTP_XOR_WriteProcessMemory_b232 {
  strings:
    $key_b232 = { e5 40 [2] d7 62 [2] d1 57 [2] ff 57 [2] c0 4b }

  condition:
    any of them
}