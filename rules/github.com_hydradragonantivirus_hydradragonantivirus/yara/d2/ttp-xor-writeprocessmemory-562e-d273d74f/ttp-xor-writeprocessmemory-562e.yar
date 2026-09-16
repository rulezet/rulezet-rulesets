rule TTP_XOR_WriteProcessMemory_562e {
  strings:
    $key_562e = { 01 5c [2] 33 7e [2] 35 4b [2] 1b 4b [2] 24 57 }

  condition:
    any of them
}