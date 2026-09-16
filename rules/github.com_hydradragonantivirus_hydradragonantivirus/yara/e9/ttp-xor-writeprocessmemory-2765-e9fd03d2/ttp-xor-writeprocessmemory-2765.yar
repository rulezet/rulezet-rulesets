rule TTP_XOR_WriteProcessMemory_2765 {
  strings:
    $key_2765 = { 70 17 [2] 42 35 [2] 44 00 [2] 6a 00 [2] 55 1c }

  condition:
    any of them
}