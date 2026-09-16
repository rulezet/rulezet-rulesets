rule TTP_XOR_WriteProcessMemory_a44a {
  strings:
    $key_a44a = { f3 38 [2] c1 1a [2] c7 2f [2] e9 2f [2] d6 33 }

  condition:
    any of them
}