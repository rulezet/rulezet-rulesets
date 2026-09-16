rule TTP_XOR_WriteProcessMemory_b44d {
  strings:
    $key_b44d = { e3 3f [2] d1 1d [2] d7 28 [2] f9 28 [2] c6 34 }

  condition:
    any of them
}