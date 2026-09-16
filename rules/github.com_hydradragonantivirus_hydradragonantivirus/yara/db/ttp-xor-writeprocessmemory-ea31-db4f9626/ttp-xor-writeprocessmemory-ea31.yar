rule TTP_XOR_WriteProcessMemory_ea31 {
  strings:
    $key_ea31 = { bd 43 [2] 8f 61 [2] 89 54 [2] a7 54 [2] 98 48 }

  condition:
    any of them
}