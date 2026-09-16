rule TTP_XOR_WriteProcessMemory_b45f {
  strings:
    $key_b45f = { e3 2d [2] d1 0f [2] d7 3a [2] f9 3a [2] c6 26 }

  condition:
    any of them
}