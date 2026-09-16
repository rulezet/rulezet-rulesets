rule TTP_XOR_WriteProcessMemory_8e17 {
  strings:
    $key_8e17 = { d9 65 [2] eb 47 [2] ed 72 [2] c3 72 [2] fc 6e }

  condition:
    any of them
}