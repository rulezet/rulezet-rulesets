rule TTP_XOR_WriteProcessMemory_e8be {
  strings:
    $key_e8be = { bf cc [2] 8d ee [2] 8b db [2] a5 db [2] 9a c7 }

  condition:
    any of them
}