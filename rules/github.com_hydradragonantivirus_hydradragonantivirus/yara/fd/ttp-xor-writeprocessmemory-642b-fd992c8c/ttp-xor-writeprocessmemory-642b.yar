rule TTP_XOR_WriteProcessMemory_642b {
  strings:
    $key_642b = { 33 59 [2] 01 7b [2] 07 4e [2] 29 4e [2] 16 52 }

  condition:
    any of them
}