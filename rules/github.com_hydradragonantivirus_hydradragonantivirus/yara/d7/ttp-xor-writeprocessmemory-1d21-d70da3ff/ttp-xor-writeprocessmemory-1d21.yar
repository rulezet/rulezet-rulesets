rule TTP_XOR_WriteProcessMemory_1d21 {
  strings:
    $key_1d21 = { 4a 53 [2] 78 71 [2] 7e 44 [2] 50 44 [2] 6f 58 }

  condition:
    any of them
}