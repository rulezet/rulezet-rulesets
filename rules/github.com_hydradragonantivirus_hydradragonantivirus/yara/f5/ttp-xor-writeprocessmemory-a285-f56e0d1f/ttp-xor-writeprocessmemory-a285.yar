rule TTP_XOR_WriteProcessMemory_a285 {
  strings:
    $key_a285 = { f5 f7 [2] c7 d5 [2] c1 e0 [2] ef e0 [2] d0 fc }

  condition:
    any of them
}