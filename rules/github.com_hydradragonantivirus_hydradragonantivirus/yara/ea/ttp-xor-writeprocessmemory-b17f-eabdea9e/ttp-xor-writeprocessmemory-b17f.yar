rule TTP_XOR_WriteProcessMemory_b17f {
  strings:
    $key_b17f = { e6 0d [2] d4 2f [2] d2 1a [2] fc 1a [2] c3 06 }

  condition:
    any of them
}