rule TTP_XOR_WriteProcessMemory_466e {
  strings:
    $key_466e = { 11 1c [2] 23 3e [2] 25 0b [2] 0b 0b [2] 34 17 }

  condition:
    any of them
}