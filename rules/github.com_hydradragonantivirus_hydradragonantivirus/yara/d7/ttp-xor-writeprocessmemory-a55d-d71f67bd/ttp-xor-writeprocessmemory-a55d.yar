rule TTP_XOR_WriteProcessMemory_a55d {
  strings:
    $key_a55d = { f2 2f [2] c0 0d [2] c6 38 [2] e8 38 [2] d7 24 }

  condition:
    any of them
}