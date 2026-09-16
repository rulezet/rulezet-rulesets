rule TTP_XOR_WriteProcessMemory_e615 {
  strings:
    $key_e615 = { b1 67 [2] 83 45 [2] 85 70 [2] ab 70 [2] 94 6c }

  condition:
    any of them
}