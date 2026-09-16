rule TTP_XOR_WriteProcessMemory_0666 {
  strings:
    $key_0666 = { 51 14 [2] 63 36 [2] 65 03 [2] 4b 03 [2] 74 1f }

  condition:
    any of them
}