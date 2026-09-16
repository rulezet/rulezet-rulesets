rule TTP_XOR_WriteProcessMemory_f0cb {
  strings:
    $key_f0cb = { a7 b9 [2] 95 9b [2] 93 ae [2] bd ae [2] 82 b2 }

  condition:
    any of them
}