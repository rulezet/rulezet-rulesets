rule TTP_XOR_WriteProcessMemory_a648 {
  strings:
    $key_a648 = { f1 3a [2] c3 18 [2] c5 2d [2] eb 2d [2] d4 31 }

  condition:
    any of them
}