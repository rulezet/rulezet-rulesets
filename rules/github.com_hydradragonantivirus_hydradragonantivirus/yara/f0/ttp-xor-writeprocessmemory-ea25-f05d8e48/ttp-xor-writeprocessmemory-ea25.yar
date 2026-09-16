rule TTP_XOR_WriteProcessMemory_ea25 {
  strings:
    $key_ea25 = { bd 57 [2] 8f 75 [2] 89 40 [2] a7 40 [2] 98 5c }

  condition:
    any of them
}