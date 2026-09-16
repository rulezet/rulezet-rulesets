rule TTP_XOR_WriteProcessMemory_f3f3 {
  strings:
    $key_f3f3 = { a4 81 [2] 96 a3 [2] 90 96 [2] be 96 [2] 81 8a }

  condition:
    any of them
}