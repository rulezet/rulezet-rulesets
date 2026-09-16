rule TTP_XOR_WriteProcessMemory_3b06 {
  strings:
    $key_3b06 = { 6c 74 [2] 5e 56 [2] 58 63 [2] 76 63 [2] 49 7f }

  condition:
    any of them
}