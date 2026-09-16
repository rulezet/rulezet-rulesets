rule TTP_XOR_WriteProcessMemory_b7bc {
  strings:
    $key_b7bc = { e0 ce [2] d2 ec [2] d4 d9 [2] fa d9 [2] c5 c5 }

  condition:
    any of them
}