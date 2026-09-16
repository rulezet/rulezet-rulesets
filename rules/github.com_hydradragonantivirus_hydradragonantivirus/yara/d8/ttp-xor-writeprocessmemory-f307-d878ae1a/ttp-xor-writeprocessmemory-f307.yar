rule TTP_XOR_WriteProcessMemory_f307 {
  strings:
    $key_f307 = { a4 75 [2] 96 57 [2] 90 62 [2] be 62 [2] 81 7e }

  condition:
    any of them
}