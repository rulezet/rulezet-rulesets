rule TTP_XOR_WriteProcessMemory_0b97 {
  strings:
    $key_0b97 = { 5c e5 [2] 6e c7 [2] 68 f2 [2] 46 f2 [2] 79 ee }

  condition:
    any of them
}