rule TTP_XOR_WriteProcessMemory_f3f0 {
  strings:
    $key_f3f0 = { a4 82 [2] 96 a0 [2] 90 95 [2] be 95 [2] 81 89 }

  condition:
    any of them
}