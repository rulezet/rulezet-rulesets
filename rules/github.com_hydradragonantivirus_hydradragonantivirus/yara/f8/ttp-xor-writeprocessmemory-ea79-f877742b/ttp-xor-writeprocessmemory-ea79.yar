rule TTP_XOR_WriteProcessMemory_ea79 {
  strings:
    $key_ea79 = { bd 0b [2] 8f 29 [2] 89 1c [2] a7 1c [2] 98 00 }

  condition:
    any of them
}