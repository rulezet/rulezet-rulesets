rule TTP_XOR_WriteProcessMemory_5044 {
  strings:
    $key_5044 = { 07 36 [2] 35 14 [2] 33 21 [2] 1d 21 [2] 22 3d }

  condition:
    any of them
}