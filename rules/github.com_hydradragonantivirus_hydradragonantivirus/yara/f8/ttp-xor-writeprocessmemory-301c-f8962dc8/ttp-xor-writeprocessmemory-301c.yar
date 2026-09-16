rule TTP_XOR_WriteProcessMemory_301c {
  strings:
    $key_301c = { 67 6e [2] 55 4c [2] 53 79 [2] 7d 79 [2] 42 65 }

  condition:
    any of them
}