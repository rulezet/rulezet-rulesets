rule TTP_XOR_WriteProcessMemory_f6be {
  strings:
    $key_f6be = { a1 cc [2] 93 ee [2] 95 db [2] bb db [2] 84 c7 }

  condition:
    any of them
}