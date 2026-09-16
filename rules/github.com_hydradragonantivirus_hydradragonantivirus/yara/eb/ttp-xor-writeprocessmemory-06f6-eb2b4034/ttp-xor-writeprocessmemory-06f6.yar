rule TTP_XOR_WriteProcessMemory_06f6 {
  strings:
    $key_06f6 = { 51 84 [2] 63 a6 [2] 65 93 [2] 4b 93 [2] 74 8f }

  condition:
    any of them
}