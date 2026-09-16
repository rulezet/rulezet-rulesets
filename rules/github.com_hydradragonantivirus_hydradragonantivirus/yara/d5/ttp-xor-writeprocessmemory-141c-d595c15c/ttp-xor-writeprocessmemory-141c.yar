rule TTP_XOR_WriteProcessMemory_141c {
  strings:
    $key_141c = { 43 6e [2] 71 4c [2] 77 79 [2] 59 79 [2] 66 65 }

  condition:
    any of them
}