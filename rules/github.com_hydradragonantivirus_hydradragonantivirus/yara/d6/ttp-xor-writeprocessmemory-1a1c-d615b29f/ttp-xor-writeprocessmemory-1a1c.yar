rule TTP_XOR_WriteProcessMemory_1a1c {
  strings:
    $key_1a1c = { 4d 6e [2] 7f 4c [2] 79 79 [2] 57 79 [2] 68 65 }

  condition:
    any of them
}