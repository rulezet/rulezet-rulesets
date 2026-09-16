rule TTP_XOR_WriteProcessMemory_b525 {
  strings:
    $key_b525 = { e2 57 [2] d0 75 [2] d6 40 [2] f8 40 [2] c7 5c }

  condition:
    any of them
}