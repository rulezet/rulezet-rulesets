rule TTP_XOR_WriteProcessMemory_8ee5 {
  strings:
    $key_8ee5 = { d9 97 [2] eb b5 [2] ed 80 [2] c3 80 [2] fc 9c }

  condition:
    any of them
}