rule TTP_XOR_WriteProcessMemory_8e55 {
  strings:
    $key_8e55 = { d9 27 [2] eb 05 [2] ed 30 [2] c3 30 [2] fc 2c }

  condition:
    any of them
}