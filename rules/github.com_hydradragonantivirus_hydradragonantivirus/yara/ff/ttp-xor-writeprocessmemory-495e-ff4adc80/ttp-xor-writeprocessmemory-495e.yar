rule TTP_XOR_WriteProcessMemory_495e {
  strings:
    $key_495e = { 1e 2c [2] 2c 0e [2] 2a 3b [2] 04 3b [2] 3b 27 }

  condition:
    any of them
}