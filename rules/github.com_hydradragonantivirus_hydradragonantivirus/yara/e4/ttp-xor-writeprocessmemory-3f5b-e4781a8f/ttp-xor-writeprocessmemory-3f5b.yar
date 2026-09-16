rule TTP_XOR_WriteProcessMemory_3f5b {
  strings:
    $key_3f5b = { 68 29 [2] 5a 0b [2] 5c 3e [2] 72 3e [2] 4d 22 }

  condition:
    any of them
}