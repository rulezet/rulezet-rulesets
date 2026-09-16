rule TTP_XOR_WriteProcessMemory_f376 {
  strings:
    $key_f376 = { a4 04 [2] 96 26 [2] 90 13 [2] be 13 [2] 81 0f }

  condition:
    any of them
}