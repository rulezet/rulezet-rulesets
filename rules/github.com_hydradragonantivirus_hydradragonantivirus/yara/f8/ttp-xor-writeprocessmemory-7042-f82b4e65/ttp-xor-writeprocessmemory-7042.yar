rule TTP_XOR_WriteProcessMemory_7042 {
  strings:
    $key_7042 = { 27 30 [2] 15 12 [2] 13 27 [2] 3d 27 [2] 02 3b }

  condition:
    any of them
}