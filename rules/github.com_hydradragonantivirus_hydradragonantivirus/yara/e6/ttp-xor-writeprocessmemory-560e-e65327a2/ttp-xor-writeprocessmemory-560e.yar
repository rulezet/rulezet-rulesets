rule TTP_XOR_WriteProcessMemory_560e {
  strings:
    $key_560e = { 01 7c [2] 33 5e [2] 35 6b [2] 1b 6b [2] 24 77 }

  condition:
    any of them
}