rule TTP_XOR_WriteProcessMemory_3f6b {
  strings:
    $key_3f6b = { 68 19 [2] 5a 3b [2] 5c 0e [2] 72 0e [2] 4d 12 }

  condition:
    any of them
}