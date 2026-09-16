rule TTP_XOR_WriteProcessMemory_276c {
  strings:
    $key_276c = { 70 1e [2] 42 3c [2] 44 09 [2] 6a 09 [2] 55 15 }

  condition:
    any of them
}