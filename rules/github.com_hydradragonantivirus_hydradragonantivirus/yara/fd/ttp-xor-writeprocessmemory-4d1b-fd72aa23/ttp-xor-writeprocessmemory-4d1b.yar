rule TTP_XOR_WriteProcessMemory_4d1b {
  strings:
    $key_4d1b = { 1a 69 [2] 28 4b [2] 2e 7e [2] 00 7e [2] 3f 62 }

  condition:
    any of them
}