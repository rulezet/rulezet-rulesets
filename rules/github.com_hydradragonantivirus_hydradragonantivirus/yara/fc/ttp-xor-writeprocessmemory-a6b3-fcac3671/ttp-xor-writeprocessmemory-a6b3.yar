rule TTP_XOR_WriteProcessMemory_a6b3 {
  strings:
    $key_a6b3 = { f1 c1 [2] c3 e3 [2] c5 d6 [2] eb d6 [2] d4 ca }

  condition:
    any of them
}