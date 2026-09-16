rule TTP_XOR_WriteProcessMemory_a731 {
  strings:
    $key_a731 = { f0 43 [2] c2 61 [2] c4 54 [2] ea 54 [2] d5 48 }

  condition:
    any of them
}