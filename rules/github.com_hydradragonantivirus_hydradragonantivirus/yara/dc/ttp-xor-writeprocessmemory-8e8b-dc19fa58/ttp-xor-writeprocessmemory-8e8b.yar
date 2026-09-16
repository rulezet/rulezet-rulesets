rule TTP_XOR_WriteProcessMemory_8e8b {
  strings:
    $key_8e8b = { d9 f9 [2] eb db [2] ed ee [2] c3 ee [2] fc f2 }

  condition:
    any of them
}