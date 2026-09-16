rule TTP_XOR_WriteProcessMemory_671c {
  strings:
    $key_671c = { 30 6e [2] 02 4c [2] 04 79 [2] 2a 79 [2] 15 65 }

  condition:
    any of them
}