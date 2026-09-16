rule TTP_XOR_WriteProcessMemory_a628 {
  strings:
    $key_a628 = { f1 5a [2] c3 78 [2] c5 4d [2] eb 4d [2] d4 51 }

  condition:
    any of them
}