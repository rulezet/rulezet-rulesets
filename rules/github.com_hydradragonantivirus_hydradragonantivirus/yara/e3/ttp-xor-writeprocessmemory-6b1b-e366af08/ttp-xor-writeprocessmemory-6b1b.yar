rule TTP_XOR_WriteProcessMemory_6b1b {
  strings:
    $key_6b1b = { 3c 69 [2] 0e 4b [2] 08 7e [2] 26 7e [2] 19 62 }

  condition:
    any of them
}