rule TTP_XOR_WriteProcessMemory_7a26 {
  strings:
    $key_7a26 = { 2d 54 [2] 1f 76 [2] 19 43 [2] 37 43 [2] 08 5f }

  condition:
    any of them
}