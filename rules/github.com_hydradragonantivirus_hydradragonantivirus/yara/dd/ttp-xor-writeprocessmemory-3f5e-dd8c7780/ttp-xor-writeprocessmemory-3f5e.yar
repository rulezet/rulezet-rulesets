rule TTP_XOR_WriteProcessMemory_3f5e {
  strings:
    $key_3f5e = { 68 2c [2] 5a 0e [2] 5c 3b [2] 72 3b [2] 4d 27 }

  condition:
    any of them
}