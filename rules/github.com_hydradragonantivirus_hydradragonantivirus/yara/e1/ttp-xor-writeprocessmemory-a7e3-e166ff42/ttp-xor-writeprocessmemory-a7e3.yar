rule TTP_XOR_WriteProcessMemory_a7e3 {
  strings:
    $key_a7e3 = { f0 91 [2] c2 b3 [2] c4 86 [2] ea 86 [2] d5 9a }

  condition:
    any of them
}