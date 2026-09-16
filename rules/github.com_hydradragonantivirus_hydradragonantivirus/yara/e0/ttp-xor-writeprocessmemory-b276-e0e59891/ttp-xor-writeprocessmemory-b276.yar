rule TTP_XOR_WriteProcessMemory_b276 {
  strings:
    $key_b276 = { e5 04 [2] d7 26 [2] d1 13 [2] ff 13 [2] c0 0f }

  condition:
    any of them
}