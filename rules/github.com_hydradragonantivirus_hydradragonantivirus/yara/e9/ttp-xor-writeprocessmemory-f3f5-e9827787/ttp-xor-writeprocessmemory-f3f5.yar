rule TTP_XOR_WriteProcessMemory_f3f5 {
  strings:
    $key_f3f5 = { a4 87 [2] 96 a5 [2] 90 90 [2] be 90 [2] 81 8c }

  condition:
    any of them
}