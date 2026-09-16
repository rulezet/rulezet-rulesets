rule TTP_XOR_WriteProcessMemory_b761 {
  strings:
    $key_b761 = { e0 13 [2] d2 31 [2] d4 04 [2] fa 04 [2] c5 18 }

  condition:
    any of them
}