rule TTP_XOR_WriteProcessMemory_5476 {
  strings:
    $key_5476 = { 03 04 [2] 31 26 [2] 37 13 [2] 19 13 [2] 26 0f }

  condition:
    any of them
}