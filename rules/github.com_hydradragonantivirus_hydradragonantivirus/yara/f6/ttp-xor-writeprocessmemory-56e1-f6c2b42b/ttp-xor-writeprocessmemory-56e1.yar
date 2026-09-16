rule TTP_XOR_WriteProcessMemory_56e1 {
  strings:
    $key_56e1 = { 01 93 [2] 33 b1 [2] 35 84 [2] 1b 84 [2] 24 98 }

  condition:
    any of them
}