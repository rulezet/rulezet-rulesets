rule TTP_XOR_WriteProcessMemory_a649 {
  strings:
    $key_a649 = { f1 3b [2] c3 19 [2] c5 2c [2] eb 2c [2] d4 30 }

  condition:
    any of them
}