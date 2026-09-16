rule TTP_XOR_WriteProcessMemory_451c {
  strings:
    $key_451c = { 12 6e [2] 20 4c [2] 26 79 [2] 08 79 [2] 37 65 }

  condition:
    any of them
}