rule TTP_XOR_WriteProcessMemory_6054 {
  strings:
    $key_6054 = { 37 26 [2] 05 04 [2] 03 31 [2] 2d 31 [2] 12 2d }

  condition:
    any of them
}