rule TTP_XOR_WriteProcessMemory_8e08 {
  strings:
    $key_8e08 = { d9 7a [2] eb 58 [2] ed 6d [2] c3 6d [2] fc 71 }

  condition:
    any of them
}