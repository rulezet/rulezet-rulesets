rule TTP_XOR_WriteProcessMemory_a55f {
  strings:
    $key_a55f = { f2 2d [2] c0 0f [2] c6 3a [2] e8 3a [2] d7 26 }

  condition:
    any of them
}