rule TTP_XOR_WriteProcessMemory_676c {
  strings:
    $key_676c = { 30 1e [2] 02 3c [2] 04 09 [2] 2a 09 [2] 15 15 }

  condition:
    any of them
}