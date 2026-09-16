rule TTP_XOR_WriteProcessMemory_f366 {
  strings:
    $key_f366 = { a4 14 [2] 96 36 [2] 90 03 [2] be 03 [2] 81 1f }

  condition:
    any of them
}