rule TTP_XOR_WriteProcessMemory_a678 {
  strings:
    $key_a678 = { f1 0a [2] c3 28 [2] c5 1d [2] eb 1d [2] d4 01 }

  condition:
    any of them
}