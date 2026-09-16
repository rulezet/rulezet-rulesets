rule TTP_XOR_WriteProcessMemory_8e02 {
  strings:
    $key_8e02 = { d9 70 [2] eb 52 [2] ed 67 [2] c3 67 [2] fc 7b }

  condition:
    any of them
}