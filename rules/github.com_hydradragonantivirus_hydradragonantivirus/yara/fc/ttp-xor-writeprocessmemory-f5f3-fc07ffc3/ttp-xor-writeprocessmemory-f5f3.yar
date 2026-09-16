rule TTP_XOR_WriteProcessMemory_f5f3 {
  strings:
    $key_f5f3 = { a2 81 [2] 90 a3 [2] 96 96 [2] b8 96 [2] 87 8a }

  condition:
    any of them
}