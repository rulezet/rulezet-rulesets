rule TTP_XOR_WriteProcessMemory_8e00 {
  strings:
    $key_8e00 = { d9 72 [2] eb 50 [2] ed 65 [2] c3 65 [2] fc 79 }

  condition:
    any of them
}