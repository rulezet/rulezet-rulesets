rule TTP_XOR_WriteProcessMemory_f782 {
  strings:
    $key_f782 = { a0 f0 [2] 92 d2 [2] 94 e7 [2] ba e7 [2] 85 fb }

  condition:
    any of them
}