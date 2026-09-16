rule TTP_XOR_WriteProcessMemory_a703 {
  strings:
    $key_a703 = { f0 71 [2] c2 53 [2] c4 66 [2] ea 66 [2] d5 7a }

  condition:
    any of them
}