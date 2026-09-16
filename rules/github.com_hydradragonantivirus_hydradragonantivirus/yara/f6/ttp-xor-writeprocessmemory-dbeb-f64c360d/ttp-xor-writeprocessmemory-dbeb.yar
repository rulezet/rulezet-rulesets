rule TTP_XOR_WriteProcessMemory_dbeb {
  strings:
    $key_dbeb = { 8c 99 [2] be bb [2] b8 8e [2] 96 8e [2] a9 92 }

  condition:
    any of them
}