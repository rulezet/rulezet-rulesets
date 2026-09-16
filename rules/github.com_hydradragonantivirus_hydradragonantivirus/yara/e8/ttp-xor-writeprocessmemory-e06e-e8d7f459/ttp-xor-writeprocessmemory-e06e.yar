rule TTP_XOR_WriteProcessMemory_e06e {
  strings:
    $key_e06e = { b7 1c [2] 85 3e [2] 83 0b [2] ad 0b [2] 92 17 }

  condition:
    any of them
}