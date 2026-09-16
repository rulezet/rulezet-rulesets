rule TTP_XOR_WriteProcessMemory_5c06 {
  strings:
    $key_5c06 = { 0b 74 [2] 39 56 [2] 3f 63 [2] 11 63 [2] 2e 7f }

  condition:
    any of them
}