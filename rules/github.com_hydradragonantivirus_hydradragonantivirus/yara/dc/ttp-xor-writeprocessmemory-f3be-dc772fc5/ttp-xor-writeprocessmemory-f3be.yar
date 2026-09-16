rule TTP_XOR_WriteProcessMemory_f3be {
  strings:
    $key_f3be = { a4 cc [2] 96 ee [2] 90 db [2] be db [2] 81 c7 }

  condition:
    any of them
}