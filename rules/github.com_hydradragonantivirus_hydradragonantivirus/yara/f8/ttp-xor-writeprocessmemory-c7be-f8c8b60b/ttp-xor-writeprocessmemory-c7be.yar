rule TTP_XOR_WriteProcessMemory_c7be {
  strings:
    $key_c7be = { 90 cc [2] a2 ee [2] a4 db [2] 8a db [2] b5 c7 }

  condition:
    any of them
}