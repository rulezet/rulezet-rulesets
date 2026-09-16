rule TTP_XOR_WriteProcessMemory_6f7e {
  strings:
    $key_6f7e = { 38 0c [2] 0a 2e [2] 0c 1b [2] 22 1b [2] 1d 07 }

  condition:
    any of them
}