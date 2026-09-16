rule TTP_XOR_WriteProcessMemory_735e {
  strings:
    $key_735e = { 24 2c [2] 16 0e [2] 10 3b [2] 3e 3b [2] 01 27 }

  condition:
    any of them
}