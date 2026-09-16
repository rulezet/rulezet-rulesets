rule TTP_XOR_WriteProcessMemory_2a3b {
  strings:
    $key_2a3b = { 7d 49 [2] 4f 6b [2] 49 5e [2] 67 5e [2] 58 42 }

  condition:
    any of them
}