rule TTP_XOR_WriteProcessMemory_2f3b {
  strings:
    $key_2f3b = { 78 49 [2] 4a 6b [2] 4c 5e [2] 62 5e [2] 5d 42 }

  condition:
    any of them
}