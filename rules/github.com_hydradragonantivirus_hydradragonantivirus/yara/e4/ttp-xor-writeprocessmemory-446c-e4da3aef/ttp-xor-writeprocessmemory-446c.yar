rule TTP_XOR_WriteProcessMemory_446c {
  strings:
    $key_446c = { 13 1e [2] 21 3c [2] 27 09 [2] 09 09 [2] 36 15 }

  condition:
    any of them
}