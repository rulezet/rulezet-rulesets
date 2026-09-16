rule TTP_XOR_WriteProcessMemory_a585 {
  strings:
    $key_a585 = { f2 f7 [2] c0 d5 [2] c6 e0 [2] e8 e0 [2] d7 fc }

  condition:
    any of them
}