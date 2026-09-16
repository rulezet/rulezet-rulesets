rule TTP_XOR_WriteProcessMemory_531b {
  strings:
    $key_531b = { 04 69 [2] 36 4b [2] 30 7e [2] 1e 7e [2] 21 62 }

  condition:
    any of them
}