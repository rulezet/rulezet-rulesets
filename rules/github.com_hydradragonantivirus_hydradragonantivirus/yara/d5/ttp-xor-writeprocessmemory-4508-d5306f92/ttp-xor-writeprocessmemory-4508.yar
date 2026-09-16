rule TTP_XOR_WriteProcessMemory_4508 {
  strings:
    $key_4508 = { 12 7a [2] 20 58 [2] 26 6d [2] 08 6d [2] 37 71 }

  condition:
    any of them
}