rule TTP_XOR_WriteProcessMemory_e4f5 {
  strings:
    $key_e4f5 = { b3 87 [2] 81 a5 [2] 87 90 [2] a9 90 [2] 96 8c }

  condition:
    any of them
}