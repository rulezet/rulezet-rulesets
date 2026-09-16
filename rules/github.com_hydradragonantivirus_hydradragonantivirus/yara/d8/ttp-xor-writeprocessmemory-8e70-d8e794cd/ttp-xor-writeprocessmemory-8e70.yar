rule TTP_XOR_WriteProcessMemory_8e70 {
  strings:
    $key_8e70 = { d9 02 [2] eb 20 [2] ed 15 [2] c3 15 [2] fc 09 }

  condition:
    any of them
}