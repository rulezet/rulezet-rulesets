rule TTP_XOR_WriteProcessMemory_4a5b {
  strings:
    $key_4a5b = { 1d 29 [2] 2f 0b [2] 29 3e [2] 07 3e [2] 38 22 }

  condition:
    any of them
}