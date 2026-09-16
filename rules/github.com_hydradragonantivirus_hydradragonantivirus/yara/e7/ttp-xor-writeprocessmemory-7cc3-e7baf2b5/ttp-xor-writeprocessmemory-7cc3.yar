rule TTP_XOR_WriteProcessMemory_7cc3 {
  strings:
    $key_7cc3 = { 2b b1 [2] 19 93 [2] 1f a6 [2] 31 a6 [2] 0e ba }

  condition:
    any of them
}