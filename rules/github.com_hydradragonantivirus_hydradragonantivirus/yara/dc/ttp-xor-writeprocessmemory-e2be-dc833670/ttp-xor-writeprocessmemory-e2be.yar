rule TTP_XOR_WriteProcessMemory_e2be {
  strings:
    $key_e2be = { b5 cc [2] 87 ee [2] 81 db [2] af db [2] 90 c7 }

  condition:
    any of them
}