rule TTP_XOR_WriteProcessMemory_8ef3 {
  strings:
    $key_8ef3 = { d9 81 [2] eb a3 [2] ed 96 [2] c3 96 [2] fc 8a }

  condition:
    any of them
}