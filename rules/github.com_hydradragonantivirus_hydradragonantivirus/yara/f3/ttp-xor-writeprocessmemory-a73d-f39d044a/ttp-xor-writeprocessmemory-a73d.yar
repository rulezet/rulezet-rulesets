rule TTP_XOR_WriteProcessMemory_a73d {
  strings:
    $key_a73d = { f0 4f [2] c2 6d [2] c4 58 [2] ea 58 [2] d5 44 }

  condition:
    any of them
}