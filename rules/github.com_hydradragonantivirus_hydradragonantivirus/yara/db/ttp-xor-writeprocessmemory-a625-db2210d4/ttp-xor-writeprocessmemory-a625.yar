rule TTP_XOR_WriteProcessMemory_a625 {
  strings:
    $key_a625 = { f1 57 [2] c3 75 [2] c5 40 [2] eb 40 [2] d4 5c }

  condition:
    any of them
}