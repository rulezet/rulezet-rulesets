rule TTP_XOR_WriteProcessMemory_545b {
  strings:
    $key_545b = { 03 29 [2] 31 0b [2] 37 3e [2] 19 3e [2] 26 22 }

  condition:
    any of them
}