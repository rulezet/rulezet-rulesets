rule TTP_XOR_WriteProcessMemory_1c5e {
  strings:
    $key_1c5e = { 4b 2c [2] 79 0e [2] 7f 3b [2] 51 3b [2] 6e 27 }

  condition:
    any of them
}