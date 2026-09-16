rule TTP_XOR_WriteProcessMemory_a0ed {
  strings:
    $key_a0ed = { f7 9f [2] c5 bd [2] c3 88 [2] ed 88 [2] d2 94 }

  condition:
    any of them
}