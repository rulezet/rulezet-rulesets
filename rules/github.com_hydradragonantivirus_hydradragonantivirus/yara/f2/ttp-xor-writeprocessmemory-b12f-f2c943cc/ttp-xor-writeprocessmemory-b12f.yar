rule TTP_XOR_WriteProcessMemory_b12f {
  strings:
    $key_b12f = { e6 5d [2] d4 7f [2] d2 4a [2] fc 4a [2] c3 56 }

  condition:
    any of them
}