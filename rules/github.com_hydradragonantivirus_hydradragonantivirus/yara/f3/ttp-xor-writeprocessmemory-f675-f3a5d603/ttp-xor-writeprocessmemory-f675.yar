rule TTP_XOR_WriteProcessMemory_f675 {
  strings:
    $key_f675 = { a1 07 [2] 93 25 [2] 95 10 [2] bb 10 [2] 84 0c }

  condition:
    any of them
}