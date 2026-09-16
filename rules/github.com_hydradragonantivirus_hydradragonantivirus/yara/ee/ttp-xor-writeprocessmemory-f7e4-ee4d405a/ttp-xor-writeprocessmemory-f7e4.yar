rule TTP_XOR_WriteProcessMemory_f7e4 {
  strings:
    $key_f7e4 = { a0 96 [2] 92 b4 [2] 94 81 [2] ba 81 [2] 85 9d }

  condition:
    any of them
}