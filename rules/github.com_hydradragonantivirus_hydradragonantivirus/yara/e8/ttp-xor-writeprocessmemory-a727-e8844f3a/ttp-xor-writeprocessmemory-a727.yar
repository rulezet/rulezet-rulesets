rule TTP_XOR_WriteProcessMemory_a727 {
  strings:
    $key_a727 = { f0 55 [2] c2 77 [2] c4 42 [2] ea 42 [2] d5 5e }

  condition:
    any of them
}