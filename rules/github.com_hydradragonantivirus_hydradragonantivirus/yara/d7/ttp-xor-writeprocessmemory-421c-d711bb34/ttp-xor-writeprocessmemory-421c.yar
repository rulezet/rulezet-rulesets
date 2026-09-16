rule TTP_XOR_WriteProcessMemory_421c {
  strings:
    $key_421c = { 15 6e [2] 27 4c [2] 21 79 [2] 0f 79 [2] 30 65 }

  condition:
    any of them
}