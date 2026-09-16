rule TTP_XOR_WriteProcessMemory_5d5e {
  strings:
    $key_5d5e = { 0a 2c [2] 38 0e [2] 3e 3b [2] 10 3b [2] 2f 27 }

  condition:
    any of them
}