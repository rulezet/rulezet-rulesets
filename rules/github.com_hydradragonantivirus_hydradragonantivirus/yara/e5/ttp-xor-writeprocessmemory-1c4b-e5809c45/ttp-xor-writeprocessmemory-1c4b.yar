rule TTP_XOR_WriteProcessMemory_1c4b {
  strings:
    $key_1c4b = { 4b 39 [2] 79 1b [2] 7f 2e [2] 51 2e [2] 6e 32 }

  condition:
    any of them
}