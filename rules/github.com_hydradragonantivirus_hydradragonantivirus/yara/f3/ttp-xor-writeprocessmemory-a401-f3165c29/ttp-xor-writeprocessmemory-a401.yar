rule TTP_XOR_WriteProcessMemory_a401 {
  strings:
    $key_a401 = { f3 73 [2] c1 51 [2] c7 64 [2] e9 64 [2] d6 78 }

  condition:
    any of them
}