rule TTP_XOR_WriteProcessMemory_a53a {
  strings:
    $key_a53a = { f2 48 [2] c0 6a [2] c6 5f [2] e8 5f [2] d7 43 }

  condition:
    any of them
}