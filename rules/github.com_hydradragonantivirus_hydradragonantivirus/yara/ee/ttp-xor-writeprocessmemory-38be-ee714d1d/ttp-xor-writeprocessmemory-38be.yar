rule TTP_XOR_WriteProcessMemory_38be {
  strings:
    $key_38be = { 6f cc [2] 5d ee [2] 5b db [2] 75 db [2] 4a c7 }

  condition:
    any of them
}