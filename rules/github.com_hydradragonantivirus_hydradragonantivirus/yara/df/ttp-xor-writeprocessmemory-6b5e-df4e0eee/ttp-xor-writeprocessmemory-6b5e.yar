rule TTP_XOR_WriteProcessMemory_6b5e {
  strings:
    $key_6b5e = { 3c 2c [2] 0e 0e [2] 08 3b [2] 26 3b [2] 19 27 }

  condition:
    any of them
}