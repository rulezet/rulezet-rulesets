rule TTP_XOR_WriteProcessMemory_89be {
  strings:
    $key_89be = { de cc [2] ec ee [2] ea db [2] c4 db [2] fb c7 }

  condition:
    any of them
}