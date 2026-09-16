rule TTP_XOR_WriteProcessMemory_a005 {
  strings:
    $key_a005 = { f7 77 [2] c5 55 [2] c3 60 [2] ed 60 [2] d2 7c }

  condition:
    any of them
}