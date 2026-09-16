rule TTP_XOR_WriteProcessMemory_f736 {
  strings:
    $key_f736 = { a0 44 [2] 92 66 [2] 94 53 [2] ba 53 [2] 85 4f }

  condition:
    any of them
}