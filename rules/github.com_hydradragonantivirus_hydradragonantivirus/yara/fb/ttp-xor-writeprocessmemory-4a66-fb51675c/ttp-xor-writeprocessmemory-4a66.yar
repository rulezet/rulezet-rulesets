rule TTP_XOR_WriteProcessMemory_4a66 {
  strings:
    $key_4a66 = { 1d 14 [2] 2f 36 [2] 29 03 [2] 07 03 [2] 38 1f }

  condition:
    any of them
}