rule TTP_XOR_WriteProcessMemory_4444 {
  strings:
    $key_4444 = { 13 36 [2] 21 14 [2] 27 21 [2] 09 21 [2] 36 3d }

  condition:
    any of them
}