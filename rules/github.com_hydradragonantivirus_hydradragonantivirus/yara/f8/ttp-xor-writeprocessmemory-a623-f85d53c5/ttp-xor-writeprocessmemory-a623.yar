rule TTP_XOR_WriteProcessMemory_a623 {
  strings:
    $key_a623 = { f1 51 [2] c3 73 [2] c5 46 [2] eb 46 [2] d4 5a }

  condition:
    any of them
}