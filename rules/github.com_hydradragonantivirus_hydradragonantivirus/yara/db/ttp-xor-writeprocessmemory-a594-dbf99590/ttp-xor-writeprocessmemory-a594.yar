rule TTP_XOR_WriteProcessMemory_a594 {
  strings:
    $key_a594 = { f2 e6 [2] c0 c4 [2] c6 f1 [2] e8 f1 [2] d7 ed }

  condition:
    any of them
}