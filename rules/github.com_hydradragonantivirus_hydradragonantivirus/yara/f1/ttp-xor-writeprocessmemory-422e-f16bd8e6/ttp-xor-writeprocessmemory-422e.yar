rule TTP_XOR_WriteProcessMemory_422e {
  strings:
    $key_422e = { 15 5c [2] 27 7e [2] 21 4b [2] 0f 4b [2] 30 57 }

  condition:
    any of them
}