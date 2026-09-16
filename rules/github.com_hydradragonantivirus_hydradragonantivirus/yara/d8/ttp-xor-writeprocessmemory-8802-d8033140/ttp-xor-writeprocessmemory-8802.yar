rule TTP_XOR_WriteProcessMemory_8802 {
  strings:
    $key_8802 = { df 70 [2] ed 52 [2] eb 67 [2] c5 67 [2] fa 7b }

  condition:
    any of them
}