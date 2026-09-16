rule TTP_XOR_WriteProcessMemory_fbd4 {
  strings:
    $key_fbd4 = { ac a6 [2] 9e 84 [2] 98 b1 [2] b6 b1 [2] 89 ad }

  condition:
    any of them
}