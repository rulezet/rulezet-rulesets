rule TTP_XOR_WriteProcessMemory_662b {
  strings:
    $key_662b = { 31 59 [2] 03 7b [2] 05 4e [2] 2b 4e [2] 14 52 }

  condition:
    any of them
}