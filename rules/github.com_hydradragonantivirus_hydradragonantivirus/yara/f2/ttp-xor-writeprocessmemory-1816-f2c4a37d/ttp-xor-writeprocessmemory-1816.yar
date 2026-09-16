rule TTP_XOR_WriteProcessMemory_1816 {
  strings:
    $key_1816 = { 4f 64 [2] 7d 46 [2] 7b 73 [2] 55 73 [2] 6a 6f }

  condition:
    any of them
}