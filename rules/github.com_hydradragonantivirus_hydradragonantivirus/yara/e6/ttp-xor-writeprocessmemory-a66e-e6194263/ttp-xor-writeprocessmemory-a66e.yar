rule TTP_XOR_WriteProcessMemory_a66e {
  strings:
    $key_a66e = { f1 1c [2] c3 3e [2] c5 0b [2] eb 0b [2] d4 17 }

  condition:
    any of them
}