rule TTP_XOR_WriteProcessMemory_2264 {
  strings:
    $key_2264 = { 75 16 [2] 47 34 [2] 41 01 [2] 6f 01 [2] 50 1d }

  condition:
    any of them
}