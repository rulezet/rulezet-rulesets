rule TTP_XOR_WriteProcessMemory_201e {
  strings:
    $key_201e = { 77 6c [2] 45 4e [2] 43 7b [2] 6d 7b [2] 52 67 }

  condition:
    any of them
}