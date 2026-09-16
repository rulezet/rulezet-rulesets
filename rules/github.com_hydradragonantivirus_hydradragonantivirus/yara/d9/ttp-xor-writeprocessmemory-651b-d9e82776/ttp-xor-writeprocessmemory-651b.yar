rule TTP_XOR_WriteProcessMemory_651b {
  strings:
    $key_651b = { 32 69 [2] 00 4b [2] 06 7e [2] 28 7e [2] 17 62 }

  condition:
    any of them
}