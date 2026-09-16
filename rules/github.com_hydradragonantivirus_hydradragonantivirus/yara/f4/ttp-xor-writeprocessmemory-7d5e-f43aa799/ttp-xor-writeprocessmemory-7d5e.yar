rule TTP_XOR_WriteProcessMemory_7d5e {
  strings:
    $key_7d5e = { 2a 2c [2] 18 0e [2] 1e 3b [2] 30 3b [2] 0f 27 }

  condition:
    any of them
}