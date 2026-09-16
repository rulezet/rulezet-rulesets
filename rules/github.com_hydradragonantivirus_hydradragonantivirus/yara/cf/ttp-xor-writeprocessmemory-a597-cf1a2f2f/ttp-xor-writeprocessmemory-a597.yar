rule TTP_XOR_WriteProcessMemory_a597 {
  strings:
    $key_a597 = { f2 e5 [2] c0 c7 [2] c6 f2 [2] e8 f2 [2] d7 ee }

  condition:
    any of them
}