rule TTP_XOR_WriteProcessMemory_8e68 {
  strings:
    $key_8e68 = { d9 1a [2] eb 38 [2] ed 0d [2] c3 0d [2] fc 11 }

  condition:
    any of them
}