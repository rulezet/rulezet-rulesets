rule TTP_XOR_WriteProcessMemory_5f64 {
  strings:
    $key_5f64 = { 08 16 [2] 3a 34 [2] 3c 01 [2] 12 01 [2] 2d 1d }

  condition:
    any of them
}