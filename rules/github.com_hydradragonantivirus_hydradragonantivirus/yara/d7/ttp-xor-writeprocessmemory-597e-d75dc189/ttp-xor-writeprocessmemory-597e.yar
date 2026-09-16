rule TTP_XOR_WriteProcessMemory_597e {
  strings:
    $key_597e = { 0e 0c [2] 3c 2e [2] 3a 1b [2] 14 1b [2] 2b 07 }

  condition:
    any of them
}