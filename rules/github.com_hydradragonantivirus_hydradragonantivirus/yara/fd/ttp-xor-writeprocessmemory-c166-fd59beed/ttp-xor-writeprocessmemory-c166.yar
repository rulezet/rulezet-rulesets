rule TTP_XOR_WriteProcessMemory_c166 {
  strings:
    $key_c166 = { 96 14 [2] a4 36 [2] a2 03 [2] 8c 03 [2] b3 1f }

  condition:
    any of them
}