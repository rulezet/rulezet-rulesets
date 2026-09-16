rule TTP_XOR_WriteProcessMemory_a1a6 {
  strings:
    $key_a1a6 = { f6 d4 [2] c4 f6 [2] c2 c3 [2] ec c3 [2] d3 df }

  condition:
    any of them
}