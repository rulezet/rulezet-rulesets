rule TTP_XOR_WriteProcessMemory_c2be {
  strings:
    $key_c2be = { 95 cc [2] a7 ee [2] a1 db [2] 8f db [2] b0 c7 }

  condition:
    any of them
}