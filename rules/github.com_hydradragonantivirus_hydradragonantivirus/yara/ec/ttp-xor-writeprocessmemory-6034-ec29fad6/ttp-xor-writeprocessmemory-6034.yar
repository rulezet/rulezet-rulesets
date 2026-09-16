rule TTP_XOR_WriteProcessMemory_6034 {
  strings:
    $key_6034 = { 37 46 [2] 05 64 [2] 03 51 [2] 2d 51 [2] 12 4d }

  condition:
    any of them
}