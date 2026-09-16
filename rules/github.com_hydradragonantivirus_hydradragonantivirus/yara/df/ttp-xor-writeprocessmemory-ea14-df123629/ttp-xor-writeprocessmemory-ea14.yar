rule TTP_XOR_WriteProcessMemory_ea14 {
  strings:
    $key_ea14 = { bd 66 [2] 8f 44 [2] 89 71 [2] a7 71 [2] 98 6d }

  condition:
    any of them
}