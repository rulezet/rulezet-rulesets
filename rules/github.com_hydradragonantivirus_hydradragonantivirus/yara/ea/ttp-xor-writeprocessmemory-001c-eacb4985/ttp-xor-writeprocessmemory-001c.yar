rule TTP_XOR_WriteProcessMemory_001c {
  strings:
    $key_001c = { 57 6e [2] 65 4c [2] 63 79 [2] 4d 79 [2] 72 65 }

  condition:
    any of them
}