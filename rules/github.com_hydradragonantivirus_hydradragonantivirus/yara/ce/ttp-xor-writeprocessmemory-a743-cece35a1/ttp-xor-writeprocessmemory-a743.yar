rule TTP_XOR_WriteProcessMemory_a743 {
  strings:
    $key_a743 = { f0 31 [2] c2 13 [2] c4 26 [2] ea 26 [2] d5 3a }

  condition:
    any of them
}