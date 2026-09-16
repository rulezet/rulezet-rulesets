rule TTP_XOR_WriteProcessMemory_a046 {
  strings:
    $key_a046 = { f7 34 [2] c5 16 [2] c3 23 [2] ed 23 [2] d2 3f }

  condition:
    any of them
}