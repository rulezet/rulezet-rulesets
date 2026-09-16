rule TTP_XOR_WriteProcessMemory_a779 {
  strings:
    $key_a779 = { f0 0b [2] c2 29 [2] c4 1c [2] ea 1c [2] d5 00 }

  condition:
    any of them
}