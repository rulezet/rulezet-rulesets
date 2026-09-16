rule TTP_XOR_WriteProcessMemory_3b5e {
  strings:
    $key_3b5e = { 6c 2c [2] 5e 0e [2] 58 3b [2] 76 3b [2] 49 27 }

  condition:
    any of them
}