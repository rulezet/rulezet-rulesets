rule TTP_XOR_WriteProcessMemory_676e {
  strings:
    $key_676e = { 30 1c [2] 02 3e [2] 04 0b [2] 2a 0b [2] 15 17 }

  condition:
    any of them
}