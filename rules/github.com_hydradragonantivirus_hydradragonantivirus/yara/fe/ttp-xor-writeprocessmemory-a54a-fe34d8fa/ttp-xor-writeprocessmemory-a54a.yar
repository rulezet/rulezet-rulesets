rule TTP_XOR_WriteProcessMemory_a54a {
  strings:
    $key_a54a = { f2 38 [2] c0 1a [2] c6 2f [2] e8 2f [2] d7 33 }

  condition:
    any of them
}