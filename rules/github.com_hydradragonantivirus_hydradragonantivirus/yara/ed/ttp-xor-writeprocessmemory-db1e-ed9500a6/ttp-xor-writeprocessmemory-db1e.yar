rule TTP_XOR_WriteProcessMemory_db1e {
  strings:
    $key_db1e = { 8c 6c [2] be 4e [2] b8 7b [2] 96 7b [2] a9 67 }

  condition:
    any of them
}