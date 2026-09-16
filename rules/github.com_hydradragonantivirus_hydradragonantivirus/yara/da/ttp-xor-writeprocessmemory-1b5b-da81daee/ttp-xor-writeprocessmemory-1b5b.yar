rule TTP_XOR_WriteProcessMemory_1b5b {
  strings:
    $key_1b5b = { 4c 29 [2] 7e 0b [2] 78 3e [2] 56 3e [2] 69 22 }

  condition:
    any of them
}