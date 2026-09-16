rule TTP_XOR_WriteProcessMemory_8e28 {
  strings:
    $key_8e28 = { d9 5a [2] eb 78 [2] ed 4d [2] c3 4d [2] fc 51 }

  condition:
    any of them
}