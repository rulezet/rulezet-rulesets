rule TTP_XOR_WriteProcessMemory_f354 {
  strings:
    $key_f354 = { a4 26 [2] 96 04 [2] 90 31 [2] be 31 [2] 81 2d }

  condition:
    any of them
}