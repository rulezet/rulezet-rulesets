rule TTP_XOR_WriteProcessMemory_661b {
  strings:
    $key_661b = { 31 69 [2] 03 4b [2] 05 7e [2] 2b 7e [2] 14 62 }

  condition:
    any of them
}