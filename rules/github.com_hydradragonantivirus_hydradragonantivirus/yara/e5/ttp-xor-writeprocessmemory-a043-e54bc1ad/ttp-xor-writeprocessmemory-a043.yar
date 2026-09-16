rule TTP_XOR_WriteProcessMemory_a043 {
  strings:
    $key_a043 = { f7 31 [2] c5 13 [2] c3 26 [2] ed 26 [2] d2 3a }

  condition:
    any of them
}