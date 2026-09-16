rule TTP_XOR_WriteProcessMemory_b4dd {
  strings:
    $key_b4dd = { e3 af [2] d1 8d [2] d7 b8 [2] f9 b8 [2] c6 a4 }

  condition:
    any of them
}