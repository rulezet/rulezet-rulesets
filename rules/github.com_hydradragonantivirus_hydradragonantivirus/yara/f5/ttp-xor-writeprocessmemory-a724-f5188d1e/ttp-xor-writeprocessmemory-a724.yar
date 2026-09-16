rule TTP_XOR_WriteProcessMemory_a724 {
  strings:
    $key_a724 = { f0 56 [2] c2 74 [2] c4 41 [2] ea 41 [2] d5 5d }

  condition:
    any of them
}