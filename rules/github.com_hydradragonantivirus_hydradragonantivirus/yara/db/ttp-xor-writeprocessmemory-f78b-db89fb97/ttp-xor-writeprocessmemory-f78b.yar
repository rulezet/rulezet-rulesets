rule TTP_XOR_WriteProcessMemory_f78b {
  strings:
    $key_f78b = { a0 f9 [2] 92 db [2] 94 ee [2] ba ee [2] 85 f2 }

  condition:
    any of them
}