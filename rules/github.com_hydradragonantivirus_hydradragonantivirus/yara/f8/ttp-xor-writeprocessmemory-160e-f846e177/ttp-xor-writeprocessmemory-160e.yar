rule TTP_XOR_WriteProcessMemory_160e {
  strings:
    $key_160e = { 41 7c [2] 73 5e [2] 75 6b [2] 5b 6b [2] 64 77 }

  condition:
    any of them
}