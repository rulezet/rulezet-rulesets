rule TTP_XOR_WriteProcessMemory_185e {
  strings:
    $key_185e = { 4f 2c [2] 7d 0e [2] 7b 3b [2] 55 3b [2] 6a 27 }

  condition:
    any of them
}