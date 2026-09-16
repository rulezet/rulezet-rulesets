rule TTP_XOR_WriteProcessMemory_a003 {
  strings:
    $key_a003 = { f7 71 [2] c5 53 [2] c3 66 [2] ed 66 [2] d2 7a }

  condition:
    any of them
}