rule TTP_XOR_WriteProcessMemory_256e {
  strings:
    $key_256e = { 72 1c [2] 40 3e [2] 46 0b [2] 68 0b [2] 57 17 }

  condition:
    any of them
}