rule TTP_XOR_WriteProcessMemory_632e {
  strings:
    $key_632e = { 34 5c [2] 06 7e [2] 00 4b [2] 2e 4b [2] 11 57 }

  condition:
    any of them
}