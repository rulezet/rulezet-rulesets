rule TTP_XOR_WriteProcessMemory_a77c {
  strings:
    $key_a77c = { f0 0e [2] c2 2c [2] c4 19 [2] ea 19 [2] d5 05 }

  condition:
    any of them
}