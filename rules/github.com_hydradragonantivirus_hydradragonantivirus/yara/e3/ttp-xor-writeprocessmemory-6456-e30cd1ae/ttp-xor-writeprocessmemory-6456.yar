rule TTP_XOR_WriteProcessMemory_6456 {
  strings:
    $key_6456 = { 33 24 [2] 01 06 [2] 07 33 [2] 29 33 [2] 16 2f }

  condition:
    any of them
}