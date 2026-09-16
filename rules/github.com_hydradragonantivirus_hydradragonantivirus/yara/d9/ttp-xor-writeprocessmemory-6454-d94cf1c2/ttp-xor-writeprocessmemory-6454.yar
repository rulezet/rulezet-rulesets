rule TTP_XOR_WriteProcessMemory_6454 {
  strings:
    $key_6454 = { 33 26 [2] 01 04 [2] 07 31 [2] 29 31 [2] 16 2d }

  condition:
    any of them
}