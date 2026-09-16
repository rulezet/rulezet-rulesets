rule TTP_XOR_WriteProcessMemory_f3e7 {
  strings:
    $key_f3e7 = { a4 95 [2] 96 b7 [2] 90 82 [2] be 82 [2] 81 9e }

  condition:
    any of them
}