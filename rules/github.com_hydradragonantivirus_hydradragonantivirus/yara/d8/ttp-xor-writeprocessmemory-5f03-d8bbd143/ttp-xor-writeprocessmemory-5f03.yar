rule TTP_XOR_WriteProcessMemory_5f03 {
  strings:
    $key_5f03 = { 08 71 [2] 3a 53 [2] 3c 66 [2] 12 66 [2] 2d 7a }

  condition:
    any of them
}