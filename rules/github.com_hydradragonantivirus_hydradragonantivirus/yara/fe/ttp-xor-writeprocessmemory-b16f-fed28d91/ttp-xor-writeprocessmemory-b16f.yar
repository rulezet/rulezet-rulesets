rule TTP_XOR_WriteProcessMemory_b16f {
  strings:
    $key_b16f = { e6 1d [2] d4 3f [2] d2 0a [2] fc 0a [2] c3 16 }

  condition:
    any of them
}