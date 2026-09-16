rule TTP_XOR_WriteProcessMemory_54e1 {
  strings:
    $key_54e1 = { 03 93 [2] 31 b1 [2] 37 84 [2] 19 84 [2] 26 98 }

  condition:
    any of them
}