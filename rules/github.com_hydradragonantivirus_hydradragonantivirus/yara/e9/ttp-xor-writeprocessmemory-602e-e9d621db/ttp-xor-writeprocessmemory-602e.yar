rule TTP_XOR_WriteProcessMemory_602e {
  strings:
    $key_602e = { 37 5c [2] 05 7e [2] 03 4b [2] 2d 4b [2] 12 57 }

  condition:
    any of them
}