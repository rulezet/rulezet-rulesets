rule TTP_XOR_WriteProcessMemory_7a76 {
  strings:
    $key_7a76 = { 2d 04 [2] 1f 26 [2] 19 13 [2] 37 13 [2] 08 0f }

  condition:
    any of them
}