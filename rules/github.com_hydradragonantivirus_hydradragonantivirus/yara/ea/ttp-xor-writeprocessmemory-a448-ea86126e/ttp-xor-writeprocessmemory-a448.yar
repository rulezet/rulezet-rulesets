rule TTP_XOR_WriteProcessMemory_a448 {
  strings:
    $key_a448 = { f3 3a [2] c1 18 [2] c7 2d [2] e9 2d [2] d6 31 }

  condition:
    any of them
}