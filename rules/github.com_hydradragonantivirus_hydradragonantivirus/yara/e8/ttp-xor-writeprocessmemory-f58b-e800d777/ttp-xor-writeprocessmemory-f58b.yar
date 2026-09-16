rule TTP_XOR_WriteProcessMemory_f58b {
  strings:
    $key_f58b = { a2 f9 [2] 90 db [2] 96 ee [2] b8 ee [2] 87 f2 }

  condition:
    any of them
}