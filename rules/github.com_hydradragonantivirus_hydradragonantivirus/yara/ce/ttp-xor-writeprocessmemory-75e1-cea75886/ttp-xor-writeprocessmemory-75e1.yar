rule TTP_XOR_WriteProcessMemory_75e1 {
  strings:
    $key_75e1 = { 22 93 [2] 10 b1 [2] 16 84 [2] 38 84 [2] 07 98 }

  condition:
    any of them
}