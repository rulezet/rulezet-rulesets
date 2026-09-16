rule TTP_XOR_WriteProcessMemory_3f4e {
  strings:
    $key_3f4e = { 68 3c [2] 5a 1e [2] 5c 2b [2] 72 2b [2] 4d 37 }

  condition:
    any of them
}