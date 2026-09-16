rule TTP_XOR_WriteProcessMemory_ece1 {
  strings:
    $key_ece1 = { bb 93 [2] 89 b1 [2] 8f 84 [2] a1 84 [2] 9e 98 }

  condition:
    any of them
}