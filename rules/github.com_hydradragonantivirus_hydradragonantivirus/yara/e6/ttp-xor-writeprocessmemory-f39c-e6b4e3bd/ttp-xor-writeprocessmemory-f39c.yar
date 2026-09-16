rule TTP_XOR_WriteProcessMemory_f39c {
  strings:
    $key_f39c = { a4 ee [2] 96 cc [2] 90 f9 [2] be f9 [2] 81 e5 }

  condition:
    any of them
}