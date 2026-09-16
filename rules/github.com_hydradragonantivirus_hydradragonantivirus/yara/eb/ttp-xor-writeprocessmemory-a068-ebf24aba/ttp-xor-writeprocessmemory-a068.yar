rule TTP_XOR_WriteProcessMemory_a068 {
  strings:
    $key_a068 = { f7 1a [2] c5 38 [2] c3 0d [2] ed 0d [2] d2 11 }

  condition:
    any of them
}