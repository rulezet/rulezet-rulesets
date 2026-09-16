rule TTP_XOR_WriteProcessMemory_a7f7 {
  strings:
    $key_a7f7 = { f0 85 [2] c2 a7 [2] c4 92 [2] ea 92 [2] d5 8e }

  condition:
    any of them
}