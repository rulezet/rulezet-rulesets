rule TTP_XOR_WriteProcessMemory_51be {
  strings:
    $key_51be = { 06 cc [2] 34 ee [2] 32 db [2] 1c db [2] 23 c7 }

  condition:
    any of them
}