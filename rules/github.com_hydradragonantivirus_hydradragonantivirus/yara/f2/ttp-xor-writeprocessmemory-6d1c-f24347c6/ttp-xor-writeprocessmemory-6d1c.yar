rule TTP_XOR_WriteProcessMemory_6d1c {
  strings:
    $key_6d1c = { 3a 6e [2] 08 4c [2] 0e 79 [2] 20 79 [2] 1f 65 }

  condition:
    any of them
}