rule TTP_XOR_WriteProcessMemory_762e {
  strings:
    $key_762e = { 21 5c [2] 13 7e [2] 15 4b [2] 3b 4b [2] 04 57 }

  condition:
    any of them
}