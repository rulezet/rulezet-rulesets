rule TTP_XOR_WriteProcessMemory_6f2e {
  strings:
    $key_6f2e = { 38 5c [2] 0a 7e [2] 0c 4b [2] 22 4b [2] 1d 57 }

  condition:
    any of them
}