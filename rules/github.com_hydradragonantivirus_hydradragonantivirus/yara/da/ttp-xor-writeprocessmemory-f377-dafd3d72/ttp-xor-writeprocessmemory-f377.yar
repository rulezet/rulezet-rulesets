rule TTP_XOR_WriteProcessMemory_f377 {
  strings:
    $key_f377 = { a4 05 [2] 96 27 [2] 90 12 [2] be 12 [2] 81 0e }

  condition:
    any of them
}