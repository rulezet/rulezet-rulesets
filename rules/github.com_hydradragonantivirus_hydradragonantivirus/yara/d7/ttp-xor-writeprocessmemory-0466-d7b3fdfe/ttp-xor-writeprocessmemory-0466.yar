rule TTP_XOR_WriteProcessMemory_0466 {
  strings:
    $key_0466 = { 53 14 [2] 61 36 [2] 67 03 [2] 49 03 [2] 76 1f }

  condition:
    any of them
}