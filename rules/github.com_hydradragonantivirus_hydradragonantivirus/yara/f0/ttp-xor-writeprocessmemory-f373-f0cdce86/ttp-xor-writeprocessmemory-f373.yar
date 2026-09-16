rule TTP_XOR_WriteProcessMemory_f373 {
  strings:
    $key_f373 = { a4 01 [2] 96 23 [2] 90 16 [2] be 16 [2] 81 0a }

  condition:
    any of them
}