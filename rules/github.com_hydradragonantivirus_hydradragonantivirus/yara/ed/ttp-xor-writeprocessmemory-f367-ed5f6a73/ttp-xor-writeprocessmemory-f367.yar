rule TTP_XOR_WriteProcessMemory_f367 {
  strings:
    $key_f367 = { a4 15 [2] 96 37 [2] 90 02 [2] be 02 [2] 81 1e }

  condition:
    any of them
}