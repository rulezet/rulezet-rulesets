rule TTP_XOR_WriteProcessMemory_1a3e {
  strings:
    $key_1a3e = { 4d 4c [2] 7f 6e [2] 79 5b [2] 57 5b [2] 68 47 }

  condition:
    any of them
}