rule TTP_XOR_WriteProcessMemory_17e1 {
  strings:
    $key_17e1 = { 40 93 [2] 72 b1 [2] 74 84 [2] 5a 84 [2] 65 98 }

  condition:
    any of them
}