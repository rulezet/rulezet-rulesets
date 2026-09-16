rule TTP_XOR_WriteProcessMemory_2e4e {
  strings:
    $key_2e4e = { 79 3c [2] 4b 1e [2] 4d 2b [2] 63 2b [2] 5c 37 }

  condition:
    any of them
}