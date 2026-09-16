rule TTP_XOR_WriteProcessMemory_8e73 {
  strings:
    $key_8e73 = { d9 01 [2] eb 23 [2] ed 16 [2] c3 16 [2] fc 0a }

  condition:
    any of them
}