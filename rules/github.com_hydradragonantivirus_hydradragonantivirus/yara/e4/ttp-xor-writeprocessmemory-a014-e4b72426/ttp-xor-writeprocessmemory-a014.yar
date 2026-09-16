rule TTP_XOR_WriteProcessMemory_a014 {
  strings:
    $key_a014 = { f7 66 [2] c5 44 [2] c3 71 [2] ed 71 [2] d2 6d }

  condition:
    any of them
}