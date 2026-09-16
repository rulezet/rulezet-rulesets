rule TTP_XOR_WriteProcessMemory_4ef6 {
  strings:
    $key_4ef6 = { 19 84 [2] 2b a6 [2] 2d 93 [2] 03 93 [2] 3c 8f }

  condition:
    any of them
}