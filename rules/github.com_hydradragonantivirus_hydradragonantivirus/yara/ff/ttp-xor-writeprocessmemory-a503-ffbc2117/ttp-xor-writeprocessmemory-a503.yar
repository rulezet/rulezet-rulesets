rule TTP_XOR_WriteProcessMemory_a503 {
  strings:
    $key_a503 = { f2 71 [2] c0 53 [2] c6 66 [2] e8 66 [2] d7 7a }

  condition:
    any of them
}