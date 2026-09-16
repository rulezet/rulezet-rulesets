rule TTP_XOR_WriteProcessMemory_752e {
  strings:
    $key_752e = { 22 5c [2] 10 7e [2] 16 4b [2] 38 4b [2] 07 57 }

  condition:
    any of them
}