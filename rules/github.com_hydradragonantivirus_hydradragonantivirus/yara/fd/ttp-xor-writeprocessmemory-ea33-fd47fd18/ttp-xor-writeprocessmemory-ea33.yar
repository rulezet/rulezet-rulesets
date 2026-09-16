rule TTP_XOR_WriteProcessMemory_ea33 {
  strings:
    $key_ea33 = { bd 41 [2] 8f 63 [2] 89 56 [2] a7 56 [2] 98 4a }

  condition:
    any of them
}