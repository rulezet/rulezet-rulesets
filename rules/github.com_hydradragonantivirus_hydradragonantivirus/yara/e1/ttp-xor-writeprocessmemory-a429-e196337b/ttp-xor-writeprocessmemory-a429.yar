rule TTP_XOR_WriteProcessMemory_a429 {
  strings:
    $key_a429 = { f3 5b [2] c1 79 [2] c7 4c [2] e9 4c [2] d6 50 }

  condition:
    any of them
}