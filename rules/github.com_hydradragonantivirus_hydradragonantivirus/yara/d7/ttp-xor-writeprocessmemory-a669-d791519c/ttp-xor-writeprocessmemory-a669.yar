rule TTP_XOR_WriteProcessMemory_a669 {
  strings:
    $key_a669 = { f1 1b [2] c3 39 [2] c5 0c [2] eb 0c [2] d4 10 }

  condition:
    any of them
}