rule TTP_XOR_WriteProcessMemory_6504 {
  strings:
    $key_6504 = { 32 76 [2] 00 54 [2] 06 61 [2] 28 61 [2] 17 7d }

  condition:
    any of them
}