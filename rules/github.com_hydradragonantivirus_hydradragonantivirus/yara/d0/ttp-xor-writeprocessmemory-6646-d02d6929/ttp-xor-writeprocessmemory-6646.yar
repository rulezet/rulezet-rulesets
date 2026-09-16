rule TTP_XOR_WriteProcessMemory_6646 {
  strings:
    $key_6646 = { 31 34 [2] 03 16 [2] 05 23 [2] 2b 23 [2] 14 3f }

  condition:
    any of them
}