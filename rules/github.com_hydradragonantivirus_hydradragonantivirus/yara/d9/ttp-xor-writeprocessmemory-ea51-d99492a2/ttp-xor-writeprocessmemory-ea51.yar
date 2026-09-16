rule TTP_XOR_WriteProcessMemory_ea51 {
  strings:
    $key_ea51 = { bd 23 [2] 8f 01 [2] 89 34 [2] a7 34 [2] 98 28 }

  condition:
    any of them
}