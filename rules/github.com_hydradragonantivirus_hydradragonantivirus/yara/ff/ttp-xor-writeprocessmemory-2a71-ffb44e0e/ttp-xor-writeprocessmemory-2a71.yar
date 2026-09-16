rule TTP_XOR_WriteProcessMemory_2a71 {
  strings:
    $key_2a71 = { 7d 03 [2] 4f 21 [2] 49 14 [2] 67 14 [2] 58 08 }

  condition:
    any of them
}