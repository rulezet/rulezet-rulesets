rule TTP_XOR_WriteProcessMemory_1354 {
  strings:
    $key_1354 = { 44 26 [2] 76 04 [2] 70 31 [2] 5e 31 [2] 61 2d }

  condition:
    any of them
}