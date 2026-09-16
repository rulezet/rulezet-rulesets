rule TTP_XOR_WriteProcessMemory_245e {
  strings:
    $key_245e = { 73 2c [2] 41 0e [2] 47 3b [2] 69 3b [2] 56 27 }

  condition:
    any of them
}