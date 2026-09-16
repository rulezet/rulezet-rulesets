rule TTP_XOR_WriteProcessMemory_8e46 {
  strings:
    $key_8e46 = { d9 34 [2] eb 16 [2] ed 23 [2] c3 23 [2] fc 3f }

  condition:
    any of them
}