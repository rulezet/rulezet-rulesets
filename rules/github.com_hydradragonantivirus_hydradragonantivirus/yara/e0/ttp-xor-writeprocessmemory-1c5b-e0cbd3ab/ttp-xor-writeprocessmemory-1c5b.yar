rule TTP_XOR_WriteProcessMemory_1c5b {
  strings:
    $key_1c5b = { 4b 29 [2] 79 0b [2] 7f 3e [2] 51 3e [2] 6e 22 }

  condition:
    any of them
}