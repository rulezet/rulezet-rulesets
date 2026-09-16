rule TTP_XOR_WriteProcessMemory_f615 {
  strings:
    $key_f615 = { a1 67 [2] 93 45 [2] 95 70 [2] bb 70 [2] 84 6c }

  condition:
    any of them
}