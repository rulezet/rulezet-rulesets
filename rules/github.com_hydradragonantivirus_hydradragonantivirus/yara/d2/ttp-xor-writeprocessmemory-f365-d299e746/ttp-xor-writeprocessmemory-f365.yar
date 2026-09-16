rule TTP_XOR_WriteProcessMemory_f365 {
  strings:
    $key_f365 = { a4 17 [2] 96 35 [2] 90 00 [2] be 00 [2] 81 1c }

  condition:
    any of them
}