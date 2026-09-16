rule TTP_XOR_WriteProcessMemory_637e {
  strings:
    $key_637e = { 34 0c [2] 06 2e [2] 00 1b [2] 2e 1b [2] 11 07 }

  condition:
    any of them
}