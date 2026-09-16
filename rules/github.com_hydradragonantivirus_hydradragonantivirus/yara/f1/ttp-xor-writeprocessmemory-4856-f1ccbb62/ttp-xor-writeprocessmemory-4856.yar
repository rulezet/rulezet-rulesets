rule TTP_XOR_WriteProcessMemory_4856 {
  strings:
    $key_4856 = { 1f 24 [2] 2d 06 [2] 2b 33 [2] 05 33 [2] 3a 2f }

  condition:
    any of them
}