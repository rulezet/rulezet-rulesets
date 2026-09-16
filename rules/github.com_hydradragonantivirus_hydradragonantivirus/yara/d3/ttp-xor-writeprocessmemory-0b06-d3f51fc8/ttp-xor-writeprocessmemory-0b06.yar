rule TTP_XOR_WriteProcessMemory_0b06 {
  strings:
    $key_0b06 = { 5c 74 [2] 6e 56 [2] 68 63 [2] 46 63 [2] 79 7f }

  condition:
    any of them
}