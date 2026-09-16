rule TTP_XOR_WriteProcessMemory_f2e0 {
  strings:
    $key_f2e0 = { a5 92 [2] 97 b0 [2] 91 85 [2] bf 85 [2] 80 99 }

  condition:
    any of them
}