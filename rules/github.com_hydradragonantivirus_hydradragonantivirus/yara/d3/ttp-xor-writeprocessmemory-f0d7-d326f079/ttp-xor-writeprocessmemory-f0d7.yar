rule TTP_XOR_WriteProcessMemory_f0d7 {
  strings:
    $key_f0d7 = { a7 a5 [2] 95 87 [2] 93 b2 [2] bd b2 [2] 82 ae }

  condition:
    any of them
}