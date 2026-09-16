rule TTP_XOR_WriteProcessMemory_6c5e {
  strings:
    $key_6c5e = { 3b 2c [2] 09 0e [2] 0f 3b [2] 21 3b [2] 1e 27 }

  condition:
    any of them
}