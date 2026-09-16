rule TTP_XOR_WriteProcessMemory_a723 {
  strings:
    $key_a723 = { f0 51 [2] c2 73 [2] c4 46 [2] ea 46 [2] d5 5a }

  condition:
    any of them
}