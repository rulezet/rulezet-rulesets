rule TTP_XOR_WriteProcessMemory_8e57 {
  strings:
    $key_8e57 = { d9 25 [2] eb 07 [2] ed 32 [2] c3 32 [2] fc 2e }

  condition:
    any of them
}