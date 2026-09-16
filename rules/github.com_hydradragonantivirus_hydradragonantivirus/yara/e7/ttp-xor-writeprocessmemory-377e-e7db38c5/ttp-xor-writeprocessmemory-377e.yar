rule TTP_XOR_WriteProcessMemory_377e {
  strings:
    $key_377e = { 60 0c [2] 52 2e [2] 54 1b [2] 7a 1b [2] 45 07 }

  condition:
    any of them
}