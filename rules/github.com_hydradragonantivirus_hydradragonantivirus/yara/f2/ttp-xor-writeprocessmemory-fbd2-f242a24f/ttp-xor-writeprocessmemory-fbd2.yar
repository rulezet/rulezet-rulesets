rule TTP_XOR_WriteProcessMemory_fbd2 {
  strings:
    $key_fbd2 = { ac a0 [2] 9e 82 [2] 98 b7 [2] b6 b7 [2] 89 ab }

  condition:
    any of them
}