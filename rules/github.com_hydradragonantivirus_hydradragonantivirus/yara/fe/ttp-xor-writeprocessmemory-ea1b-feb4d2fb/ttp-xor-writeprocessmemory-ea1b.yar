rule TTP_XOR_WriteProcessMemory_ea1b {
  strings:
    $key_ea1b = { bd 69 [2] 8f 4b [2] 89 7e [2] a7 7e [2] 98 62 }

  condition:
    any of them
}