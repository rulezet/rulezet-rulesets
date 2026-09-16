rule TTP_XOR_WriteProcessMemory_f374 {
  strings:
    $key_f374 = { a4 06 [2] 96 24 [2] 90 11 [2] be 11 [2] 81 0d }

  condition:
    any of them
}