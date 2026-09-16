rule TTP_XOR_WriteProcessMemory_27e1 {
  strings:
    $key_27e1 = { 70 93 [2] 42 b1 [2] 44 84 [2] 6a 84 [2] 55 98 }

  condition:
    any of them
}