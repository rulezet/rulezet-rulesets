rule TTP_XOR_WriteProcessMemory_441e {
  strings:
    $key_441e = { 13 6c [2] 21 4e [2] 27 7b [2] 09 7b [2] 36 67 }

  condition:
    any of them
}