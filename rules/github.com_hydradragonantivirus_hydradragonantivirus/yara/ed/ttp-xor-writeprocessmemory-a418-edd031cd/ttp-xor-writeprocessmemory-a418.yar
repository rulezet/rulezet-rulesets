rule TTP_XOR_WriteProcessMemory_a418 {
  strings:
    $key_a418 = { f3 6a [2] c1 48 [2] c7 7d [2] e9 7d [2] d6 61 }

  condition:
    any of them
}