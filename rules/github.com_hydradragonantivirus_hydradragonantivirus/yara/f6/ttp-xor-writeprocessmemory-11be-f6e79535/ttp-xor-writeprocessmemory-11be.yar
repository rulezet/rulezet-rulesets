rule TTP_XOR_WriteProcessMemory_11be {
  strings:
    $key_11be = { 46 cc [2] 74 ee [2] 72 db [2] 5c db [2] 63 c7 }

  condition:
    any of them
}