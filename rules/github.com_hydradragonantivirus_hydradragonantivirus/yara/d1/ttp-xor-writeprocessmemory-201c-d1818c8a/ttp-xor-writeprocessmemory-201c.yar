rule TTP_XOR_WriteProcessMemory_201c {
  strings:
    $key_201c = { 77 6e [2] 45 4c [2] 43 79 [2] 6d 79 [2] 52 65 }

  condition:
    any of them
}