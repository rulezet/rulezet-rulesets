rule TTP_XOR_WriteProcessMemory_56d2 {
  strings:
    $key_56d2 = { 01 a0 [2] 33 82 [2] 35 b7 [2] 1b b7 [2] 24 ab }

  condition:
    any of them
}