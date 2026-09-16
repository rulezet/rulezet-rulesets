rule TTP_XOR_WriteProcessMemory_6d6b {
  strings:
    $key_6d6b = { 3a 19 [2] 08 3b [2] 0e 0e [2] 20 0e [2] 1f 12 }

  condition:
    any of them
}