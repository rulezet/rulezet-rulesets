rule TTP_XOR_WriteProcessMemory_b2be {
  strings:
    $key_b2be = { e5 cc [2] d7 ee [2] d1 db [2] ff db [2] c0 c7 }

  condition:
    any of them
}