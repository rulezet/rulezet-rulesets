rule TTP_XOR_WriteProcessMemory_34e1 {
  strings:
    $key_34e1 = { 63 93 [2] 51 b1 [2] 57 84 [2] 79 84 [2] 46 98 }

  condition:
    any of them
}