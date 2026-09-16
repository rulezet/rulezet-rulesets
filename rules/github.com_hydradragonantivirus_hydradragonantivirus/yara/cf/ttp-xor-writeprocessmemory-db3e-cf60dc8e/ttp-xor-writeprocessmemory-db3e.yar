rule TTP_XOR_WriteProcessMemory_db3e {
  strings:
    $key_db3e = { 8c 4c [2] be 6e [2] b8 5b [2] 96 5b [2] a9 47 }

  condition:
    any of them
}