rule TTP_XOR_WriteProcessMemory_ea6e {
  strings:
    $key_ea6e = { bd 1c [2] 8f 3e [2] 89 0b [2] a7 0b [2] 98 17 }

  condition:
    any of them
}