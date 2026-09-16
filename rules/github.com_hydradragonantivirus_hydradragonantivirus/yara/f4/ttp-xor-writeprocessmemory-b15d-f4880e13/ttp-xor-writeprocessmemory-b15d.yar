rule TTP_XOR_WriteProcessMemory_b15d {
  strings:
    $key_b15d = { e6 2f [2] d4 0d [2] d2 38 [2] fc 38 [2] c3 24 }

  condition:
    any of them
}