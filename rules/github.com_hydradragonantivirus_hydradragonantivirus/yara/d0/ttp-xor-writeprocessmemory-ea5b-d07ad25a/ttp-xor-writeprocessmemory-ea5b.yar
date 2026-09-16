rule TTP_XOR_WriteProcessMemory_ea5b {
  strings:
    $key_ea5b = { bd 29 [2] 8f 0b [2] 89 3e [2] a7 3e [2] 98 22 }

  condition:
    any of them
}