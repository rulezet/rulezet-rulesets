rule TTP_XOR_WriteProcessMemory_4a1e {
  strings:
    $key_4a1e = { 1d 6c [2] 2f 4e [2] 29 7b [2] 07 7b [2] 38 67 }

  condition:
    any of them
}