rule TTP_XOR_WriteProcessMemory_500e {
  strings:
    $key_500e = { 07 7c [2] 35 5e [2] 33 6b [2] 1d 6b [2] 22 77 }

  condition:
    any of them
}