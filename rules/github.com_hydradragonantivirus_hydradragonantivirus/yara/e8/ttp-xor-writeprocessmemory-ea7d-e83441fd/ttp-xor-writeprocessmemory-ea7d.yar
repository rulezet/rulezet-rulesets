rule TTP_XOR_WriteProcessMemory_ea7d {
  strings:
    $key_ea7d = { bd 0f [2] 8f 2d [2] 89 18 [2] a7 18 [2] 98 04 }

  condition:
    any of them
}