rule TTP_XOR_WriteProcessMemory_71e1 {
  strings:
    $key_71e1 = { 26 93 [2] 14 b1 [2] 12 84 [2] 3c 84 [2] 03 98 }

  condition:
    any of them
}