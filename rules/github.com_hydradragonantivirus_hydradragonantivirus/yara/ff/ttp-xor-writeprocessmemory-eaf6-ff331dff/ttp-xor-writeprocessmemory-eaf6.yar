rule TTP_XOR_WriteProcessMemory_eaf6 {
  strings:
    $key_eaf6 = { bd 84 [2] 8f a6 [2] 89 93 [2] a7 93 [2] 98 8f }

  condition:
    any of them
}