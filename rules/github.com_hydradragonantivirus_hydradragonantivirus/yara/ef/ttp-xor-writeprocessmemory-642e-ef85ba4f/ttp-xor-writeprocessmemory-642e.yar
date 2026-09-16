rule TTP_XOR_WriteProcessMemory_642e {
  strings:
    $key_642e = { 33 5c [2] 01 7e [2] 07 4b [2] 29 4b [2] 16 57 }

  condition:
    any of them
}