rule TTP_XOR_WriteProcessMemory_4b2b {
  strings:
    $key_4b2b = { 1c 59 [2] 2e 7b [2] 28 4e [2] 06 4e [2] 39 52 }

  condition:
    any of them
}