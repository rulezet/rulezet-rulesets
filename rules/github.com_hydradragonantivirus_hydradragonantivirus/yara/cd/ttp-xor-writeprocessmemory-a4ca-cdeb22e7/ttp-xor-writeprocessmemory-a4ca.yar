rule TTP_XOR_WriteProcessMemory_a4ca {
  strings:
    $key_a4ca = { f3 b8 [2] c1 9a [2] c7 af [2] e9 af [2] d6 b3 }

  condition:
    any of them
}