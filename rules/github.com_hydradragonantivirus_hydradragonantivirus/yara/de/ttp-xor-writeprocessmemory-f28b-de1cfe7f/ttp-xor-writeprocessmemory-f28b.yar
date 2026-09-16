rule TTP_XOR_WriteProcessMemory_f28b {
  strings:
    $key_f28b = { a5 f9 [2] 97 db [2] 91 ee [2] bf ee [2] 80 f2 }

  condition:
    any of them
}