rule TTP_XOR_WriteProcessMemory_a56a {
  strings:
    $key_a56a = { f2 18 [2] c0 3a [2] c6 0f [2] e8 0f [2] d7 13 }

  condition:
    any of them
}