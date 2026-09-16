rule TTP_XOR_WriteProcessMemory_8e72 {
  strings:
    $key_8e72 = { d9 00 [2] eb 22 [2] ed 17 [2] c3 17 [2] fc 0b }

  condition:
    any of them
}