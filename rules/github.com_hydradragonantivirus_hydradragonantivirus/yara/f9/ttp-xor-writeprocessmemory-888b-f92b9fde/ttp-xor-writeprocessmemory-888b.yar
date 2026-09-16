rule TTP_XOR_WriteProcessMemory_888b {
  strings:
    $key_888b = { df f9 [2] ed db [2] eb ee [2] c5 ee [2] fa f2 }

  condition:
    any of them
}