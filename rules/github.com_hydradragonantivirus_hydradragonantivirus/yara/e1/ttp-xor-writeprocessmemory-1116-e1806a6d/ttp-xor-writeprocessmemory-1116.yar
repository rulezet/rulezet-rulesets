rule TTP_XOR_WriteProcessMemory_1116 {
  strings:
    $key_1116 = { 46 64 [2] 74 46 [2] 72 73 [2] 5c 73 [2] 63 6f }

  condition:
    any of them
}