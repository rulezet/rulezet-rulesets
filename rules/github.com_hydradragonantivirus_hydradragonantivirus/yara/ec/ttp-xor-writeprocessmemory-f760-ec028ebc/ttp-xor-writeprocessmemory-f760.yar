rule TTP_XOR_WriteProcessMemory_f760 {
  strings:
    $key_f760 = { a0 12 [2] 92 30 [2] 94 05 [2] ba 05 [2] 85 19 }

  condition:
    any of them
}