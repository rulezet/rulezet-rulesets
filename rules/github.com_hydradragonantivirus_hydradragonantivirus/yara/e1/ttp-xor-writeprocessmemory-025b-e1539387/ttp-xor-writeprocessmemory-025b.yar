rule TTP_XOR_WriteProcessMemory_025b {
  strings:
    $key_025b = { 55 29 [2] 67 0b [2] 61 3e [2] 4f 3e [2] 70 22 }

  condition:
    any of them
}