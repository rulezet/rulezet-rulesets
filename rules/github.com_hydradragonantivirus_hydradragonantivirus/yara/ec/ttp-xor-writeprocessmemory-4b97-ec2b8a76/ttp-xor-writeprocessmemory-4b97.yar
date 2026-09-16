rule TTP_XOR_WriteProcessMemory_4b97 {
  strings:
    $key_4b97 = { 1c e5 [2] 2e c7 [2] 28 f2 [2] 06 f2 [2] 39 ee }

  condition:
    any of them
}