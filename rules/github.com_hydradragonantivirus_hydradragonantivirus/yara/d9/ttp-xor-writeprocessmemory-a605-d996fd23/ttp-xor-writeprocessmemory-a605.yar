rule TTP_XOR_WriteProcessMemory_a605 {
  strings:
    $key_a605 = { f1 77 [2] c3 55 [2] c5 60 [2] eb 60 [2] d4 7c }

  condition:
    any of them
}