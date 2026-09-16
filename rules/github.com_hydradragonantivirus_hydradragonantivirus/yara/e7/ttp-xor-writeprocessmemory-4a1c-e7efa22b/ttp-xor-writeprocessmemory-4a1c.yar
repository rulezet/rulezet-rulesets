rule TTP_XOR_WriteProcessMemory_4a1c {
  strings:
    $key_4a1c = { 1d 6e [2] 2f 4c [2] 29 79 [2] 07 79 [2] 38 65 }

  condition:
    any of them
}