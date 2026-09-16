rule TTP_XOR_WriteProcessMemory_2e1b {
  strings:
    $key_2e1b = { 79 69 [2] 4b 4b [2] 4d 7e [2] 63 7e [2] 5c 62 }

  condition:
    any of them
}