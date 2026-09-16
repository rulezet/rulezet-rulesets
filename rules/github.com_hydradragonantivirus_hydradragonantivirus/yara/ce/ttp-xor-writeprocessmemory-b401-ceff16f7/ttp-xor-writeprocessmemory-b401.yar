rule TTP_XOR_WriteProcessMemory_b401 {
  strings:
    $key_b401 = { e3 73 [2] d1 51 [2] d7 64 [2] f9 64 [2] c6 78 }

  condition:
    any of them
}