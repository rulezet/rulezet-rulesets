rule TTP_XOR_WriteProcessMemory_a048 {
  strings:
    $key_a048 = { f7 3a [2] c5 18 [2] c3 2d [2] ed 2d [2] d2 31 }

  condition:
    any of them
}