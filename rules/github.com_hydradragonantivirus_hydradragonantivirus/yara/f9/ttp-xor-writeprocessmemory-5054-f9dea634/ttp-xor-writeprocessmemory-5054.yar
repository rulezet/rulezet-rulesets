rule TTP_XOR_WriteProcessMemory_5054 {
  strings:
    $key_5054 = { 07 26 [2] 35 04 [2] 33 31 [2] 1d 31 [2] 22 2d }

  condition:
    any of them
}