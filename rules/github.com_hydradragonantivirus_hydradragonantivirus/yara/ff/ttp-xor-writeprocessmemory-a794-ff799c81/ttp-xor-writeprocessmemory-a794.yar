rule TTP_XOR_WriteProcessMemory_a794 {
  strings:
    $key_a794 = { f0 e6 [2] c2 c4 [2] c4 f1 [2] ea f1 [2] d5 ed }

  condition:
    any of them
}