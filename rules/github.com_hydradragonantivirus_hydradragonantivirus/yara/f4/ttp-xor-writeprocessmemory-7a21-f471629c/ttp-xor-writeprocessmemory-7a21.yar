rule TTP_XOR_WriteProcessMemory_7a21 {
  strings:
    $key_7a21 = { 2d 53 [2] 1f 71 [2] 19 44 [2] 37 44 [2] 08 58 }

  condition:
    any of them
}