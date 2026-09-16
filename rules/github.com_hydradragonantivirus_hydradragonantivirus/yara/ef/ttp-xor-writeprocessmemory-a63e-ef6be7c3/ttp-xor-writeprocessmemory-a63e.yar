rule TTP_XOR_WriteProcessMemory_a63e {
  strings:
    $key_a63e = { f1 4c [2] c3 6e [2] c5 5b [2] eb 5b [2] d4 47 }

  condition:
    any of them
}