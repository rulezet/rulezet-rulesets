rule TTP_XOR_WriteProcessMemory_8ee4 {
  strings:
    $key_8ee4 = { d9 96 [2] eb b4 [2] ed 81 [2] c3 81 [2] fc 9d }

  condition:
    any of them
}