rule TTP_XOR_WriteProcessMemory_b508 {
  strings:
    $key_b508 = { e2 7a [2] d0 58 [2] d6 6d [2] f8 6d [2] c7 71 }

  condition:
    any of them
}