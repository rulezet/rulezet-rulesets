rule TTP_XOR_WriteProcessMemory_626b {
  strings:
    $key_626b = { 35 19 [2] 07 3b [2] 01 0e [2] 2f 0e [2] 10 12 }

  condition:
    any of them
}