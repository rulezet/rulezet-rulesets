rule TTP_XOR_WriteProcessMemory_7021 {
  strings:
    $key_7021 = { 27 53 [2] 15 71 [2] 13 44 [2] 3d 44 [2] 02 58 }

  condition:
    any of them
}