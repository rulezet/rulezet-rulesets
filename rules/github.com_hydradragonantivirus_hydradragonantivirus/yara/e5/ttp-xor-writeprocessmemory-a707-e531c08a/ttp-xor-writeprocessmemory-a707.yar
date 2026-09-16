rule TTP_XOR_WriteProcessMemory_a707 {
  strings:
    $key_a707 = { f0 75 [2] c2 57 [2] c4 62 [2] ea 62 [2] d5 7e }

  condition:
    any of them
}