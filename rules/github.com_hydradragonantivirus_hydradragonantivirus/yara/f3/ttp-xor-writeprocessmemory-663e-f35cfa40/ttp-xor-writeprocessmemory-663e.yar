rule TTP_XOR_WriteProcessMemory_663e {
  strings:
    $key_663e = { 31 4c [2] 03 6e [2] 05 5b [2] 2b 5b [2] 14 47 }

  condition:
    any of them
}