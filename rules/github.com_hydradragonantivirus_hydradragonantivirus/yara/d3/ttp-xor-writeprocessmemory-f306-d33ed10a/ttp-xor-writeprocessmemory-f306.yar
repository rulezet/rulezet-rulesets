rule TTP_XOR_WriteProcessMemory_f306 {
  strings:
    $key_f306 = { a4 74 [2] 96 56 [2] 90 63 [2] be 63 [2] 81 7f }

  condition:
    any of them
}