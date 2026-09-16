rule TTP_XOR_WriteProcessMemory_51e1 {
  strings:
    $key_51e1 = { 06 93 [2] 34 b1 [2] 32 84 [2] 1c 84 [2] 23 98 }

  condition:
    any of them
}