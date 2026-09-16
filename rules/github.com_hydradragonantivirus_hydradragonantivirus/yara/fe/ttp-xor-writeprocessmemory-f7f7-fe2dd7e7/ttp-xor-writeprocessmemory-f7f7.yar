rule TTP_XOR_WriteProcessMemory_f7f7 {
  strings:
    $key_f7f7 = { a0 85 [2] 92 a7 [2] 94 92 [2] ba 92 [2] 85 8e }

  condition:
    any of them
}