rule TTP_XOR_WriteProcessMemory_db4e {
  strings:
    $key_db4e = { 8c 3c [2] be 1e [2] b8 2b [2] 96 2b [2] a9 37 }

  condition:
    any of them
}