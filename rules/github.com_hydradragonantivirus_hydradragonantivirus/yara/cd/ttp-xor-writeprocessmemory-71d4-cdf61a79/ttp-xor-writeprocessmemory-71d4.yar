rule TTP_XOR_WriteProcessMemory_71d4 {
  strings:
    $key_71d4 = { 26 a6 [2] 14 84 [2] 12 b1 [2] 3c b1 [2] 03 ad }

  condition:
    any of them
}