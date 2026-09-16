rule TTP_XOR_WriteProcessMemory_346c {
  strings:
    $key_346c = { 63 1e [2] 51 3c [2] 57 09 [2] 79 09 [2] 46 15 }

  condition:
    any of them
}