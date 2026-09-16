rule TTP_XOR_WriteProcessMemory_a706 {
  strings:
    $key_a706 = { f0 74 [2] c2 56 [2] c4 63 [2] ea 63 [2] d5 7f }

  condition:
    any of them
}