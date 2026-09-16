rule TTP_XOR_WriteProcessMemory_6f44 {
  strings:
    $key_6f44 = { 38 36 [2] 0a 14 [2] 0c 21 [2] 22 21 [2] 1d 3d }

  condition:
    any of them
}