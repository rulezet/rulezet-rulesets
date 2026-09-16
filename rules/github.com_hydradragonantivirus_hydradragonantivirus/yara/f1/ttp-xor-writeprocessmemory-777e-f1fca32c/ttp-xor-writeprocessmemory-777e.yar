rule TTP_XOR_WriteProcessMemory_777e {
  strings:
    $key_777e = { 20 0c [2] 12 2e [2] 14 1b [2] 3a 1b [2] 05 07 }

  condition:
    any of them
}