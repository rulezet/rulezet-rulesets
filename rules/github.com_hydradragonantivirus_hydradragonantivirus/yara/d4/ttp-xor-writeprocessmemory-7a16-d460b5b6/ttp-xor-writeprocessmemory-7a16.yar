rule TTP_XOR_WriteProcessMemory_7a16 {
  strings:
    $key_7a16 = { 2d 64 [2] 1f 46 [2] 19 73 [2] 37 73 [2] 08 6f }

  condition:
    any of them
}