rule TTP_XOR_WriteProcessMemory_2f1b {
  strings:
    $key_2f1b = { 78 69 [2] 4a 4b [2] 4c 7e [2] 62 7e [2] 5d 62 }

  condition:
    any of them
}