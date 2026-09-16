rule TTP_XOR_WriteProcessMemory_7a06 {
  strings:
    $key_7a06 = { 2d 74 [2] 1f 56 [2] 19 63 [2] 37 63 [2] 08 7f }

  condition:
    any of them
}