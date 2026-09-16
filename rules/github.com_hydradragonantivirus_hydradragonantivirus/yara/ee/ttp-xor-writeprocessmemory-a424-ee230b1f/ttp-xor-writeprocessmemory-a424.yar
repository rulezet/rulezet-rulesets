rule TTP_XOR_WriteProcessMemory_a424 {
  strings:
    $key_a424 = { f3 56 [2] c1 74 [2] c7 41 [2] e9 41 [2] d6 5d }

  condition:
    any of them
}