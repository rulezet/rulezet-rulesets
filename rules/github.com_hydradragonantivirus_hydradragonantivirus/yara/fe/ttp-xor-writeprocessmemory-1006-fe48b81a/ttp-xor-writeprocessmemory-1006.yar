rule TTP_XOR_WriteProcessMemory_1006 {
  strings:
    $key_1006 = { 47 74 [2] 75 56 [2] 73 63 [2] 5d 63 [2] 62 7f }

  condition:
    any of them
}