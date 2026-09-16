rule TTP_XOR_WriteProcessMemory_5f7e {
  strings:
    $key_5f7e = { 08 0c [2] 3a 2e [2] 3c 1b [2] 12 1b [2] 2d 07 }

  condition:
    any of them
}