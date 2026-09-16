rule TTP_XOR_WriteProcessMemory_705e {
  strings:
    $key_705e = { 27 2c [2] 15 0e [2] 13 3b [2] 3d 3b [2] 02 27 }

  condition:
    any of them
}