rule TTP_XOR_WriteProcessMemory_f355 {
  strings:
    $key_f355 = { a4 27 [2] 96 05 [2] 90 30 [2] be 30 [2] 81 2c }

  condition:
    any of them
}