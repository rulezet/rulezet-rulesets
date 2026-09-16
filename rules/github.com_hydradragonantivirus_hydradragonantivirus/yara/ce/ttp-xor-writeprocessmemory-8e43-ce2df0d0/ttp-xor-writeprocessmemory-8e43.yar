rule TTP_XOR_WriteProcessMemory_8e43 {
  strings:
    $key_8e43 = { d9 31 [2] eb 13 [2] ed 26 [2] c3 26 [2] fc 3a }

  condition:
    any of them
}