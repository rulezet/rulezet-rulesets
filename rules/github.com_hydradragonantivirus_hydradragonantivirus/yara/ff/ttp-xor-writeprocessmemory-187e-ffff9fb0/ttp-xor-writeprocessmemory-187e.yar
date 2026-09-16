rule TTP_XOR_WriteProcessMemory_187e {
  strings:
    $key_187e = { 4f 0c [2] 7d 2e [2] 7b 1b [2] 55 1b [2] 6a 07 }

  condition:
    any of them
}