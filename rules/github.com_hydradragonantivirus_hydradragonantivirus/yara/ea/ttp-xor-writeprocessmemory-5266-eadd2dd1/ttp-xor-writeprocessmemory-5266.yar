rule TTP_XOR_WriteProcessMemory_5266 {
  strings:
    $key_5266 = { 05 14 [2] 37 36 [2] 31 03 [2] 1f 03 [2] 20 1f }

  condition:
    any of them
}