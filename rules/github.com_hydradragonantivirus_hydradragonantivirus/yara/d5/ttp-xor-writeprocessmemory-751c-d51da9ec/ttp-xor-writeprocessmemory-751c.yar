rule TTP_XOR_WriteProcessMemory_751c {
  strings:
    $key_751c = { 22 6e [2] 10 4c [2] 16 79 [2] 38 79 [2] 07 65 }

  condition:
    any of them
}