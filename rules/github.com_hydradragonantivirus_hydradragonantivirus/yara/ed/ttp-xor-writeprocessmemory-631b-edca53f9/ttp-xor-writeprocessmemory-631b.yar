rule TTP_XOR_WriteProcessMemory_631b {
  strings:
    $key_631b = { 34 69 [2] 06 4b [2] 00 7e [2] 2e 7e [2] 11 62 }

  condition:
    any of them
}