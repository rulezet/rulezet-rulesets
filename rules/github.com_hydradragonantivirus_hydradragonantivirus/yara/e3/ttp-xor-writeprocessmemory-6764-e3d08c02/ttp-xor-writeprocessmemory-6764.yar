rule TTP_XOR_WriteProcessMemory_6764 {
  strings:
    $key_6764 = { 30 16 [2] 02 34 [2] 04 01 [2] 2a 01 [2] 15 1d }

  condition:
    any of them
}