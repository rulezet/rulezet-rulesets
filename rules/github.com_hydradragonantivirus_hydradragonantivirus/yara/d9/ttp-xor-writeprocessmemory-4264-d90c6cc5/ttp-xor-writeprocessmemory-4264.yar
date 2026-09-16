rule TTP_XOR_WriteProcessMemory_4264 {
  strings:
    $key_4264 = { 15 16 [2] 27 34 [2] 21 01 [2] 0f 01 [2] 30 1d }

  condition:
    any of them
}