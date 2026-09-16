rule TTP_XOR_WriteProcessMemory_4c5e {
  strings:
    $key_4c5e = { 1b 2c [2] 29 0e [2] 2f 3b [2] 01 3b [2] 3e 27 }

  condition:
    any of them
}