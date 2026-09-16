rule TTP_XOR_WriteProcessMemory_db5e {
  strings:
    $key_db5e = { 8c 2c [2] be 0e [2] b8 3b [2] 96 3b [2] a9 27 }

  condition:
    any of them
}