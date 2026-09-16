rule TTP_XOR_WriteProcessMemory_b7f8 {
  strings:
    $key_b7f8 = { e0 8a [2] d2 a8 [2] d4 9d [2] fa 9d [2] c5 81 }

  condition:
    any of them
}