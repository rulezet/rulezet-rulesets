rule TTP_XOR_WriteProcessMemory_76e1 {
  strings:
    $key_76e1 = { 21 93 [2] 13 b1 [2] 15 84 [2] 3b 84 [2] 04 98 }

  condition:
    any of them
}