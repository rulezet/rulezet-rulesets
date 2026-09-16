rule TTP_XOR_WriteProcessMemory_02e1 {
  strings:
    $key_02e1 = { 55 93 [2] 67 b1 [2] 61 84 [2] 4f 84 [2] 70 98 }

  condition:
    any of them
}