rule TTP_XOR_WriteProcessMemory_74e1 {
  strings:
    $key_74e1 = { 23 93 [2] 11 b1 [2] 17 84 [2] 39 84 [2] 06 98 }

  condition:
    any of them
}