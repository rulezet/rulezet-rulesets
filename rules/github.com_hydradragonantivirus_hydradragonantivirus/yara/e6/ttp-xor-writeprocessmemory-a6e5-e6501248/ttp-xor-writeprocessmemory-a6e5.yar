rule TTP_XOR_WriteProcessMemory_a6e5 {
  strings:
    $key_a6e5 = { f1 97 [2] c3 b5 [2] c5 80 [2] eb 80 [2] d4 9c }

  condition:
    any of them
}