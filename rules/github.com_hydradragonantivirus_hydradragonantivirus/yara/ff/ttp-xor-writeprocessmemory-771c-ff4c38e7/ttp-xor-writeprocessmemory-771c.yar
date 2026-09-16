rule TTP_XOR_WriteProcessMemory_771c {
  strings:
    $key_771c = { 20 6e [2] 12 4c [2] 14 79 [2] 3a 79 [2] 05 65 }

  condition:
    any of them
}