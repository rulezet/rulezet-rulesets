rule TTP_XOR_WriteProcessMemory_a700 {
  strings:
    $key_a700 = { f0 72 [2] c2 50 [2] c4 65 [2] ea 65 [2] d5 79 }

  condition:
    any of them
}