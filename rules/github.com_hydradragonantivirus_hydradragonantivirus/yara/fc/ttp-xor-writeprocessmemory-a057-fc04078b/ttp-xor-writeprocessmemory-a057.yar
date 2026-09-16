rule TTP_XOR_WriteProcessMemory_a057 {
  strings:
    $key_a057 = { f7 25 [2] c5 07 [2] c3 32 [2] ed 32 [2] d2 2e }

  condition:
    any of them
}