rule TTP_XOR_WriteProcessMemory_8ee8 {
  strings:
    $key_8ee8 = { d9 9a [2] eb b8 [2] ed 8d [2] c3 8d [2] fc 91 }

  condition:
    any of them
}