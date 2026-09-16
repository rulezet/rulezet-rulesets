rule TTP_XOR_WriteProcessMemory_f5e1 {
  strings:
    $key_f5e1 = { a2 93 [2] 90 b1 [2] 96 84 [2] b8 84 [2] 87 98 }

  condition:
    any of them
}