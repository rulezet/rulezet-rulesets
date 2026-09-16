rule TTP_XOR_WriteProcessMemory_a47a {
  strings:
    $key_a47a = { f3 08 [2] c1 2a [2] c7 1f [2] e9 1f [2] d6 03 }

  condition:
    any of them
}