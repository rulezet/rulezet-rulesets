rule TTP_XOR_WriteProcessMemory_741e {
  strings:
    $key_741e = { 23 6c [2] 11 4e [2] 17 7b [2] 39 7b [2] 06 67 }

  condition:
    any of them
}