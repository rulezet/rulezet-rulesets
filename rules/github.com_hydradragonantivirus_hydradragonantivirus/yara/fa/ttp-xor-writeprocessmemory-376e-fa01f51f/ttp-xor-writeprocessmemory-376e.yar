rule TTP_XOR_WriteProcessMemory_376e {
  strings:
    $key_376e = { 60 1c [2] 52 3e [2] 54 0b [2] 7a 0b [2] 45 17 }

  condition:
    any of them
}