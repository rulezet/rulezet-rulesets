rule TTP_XOR_WriteProcessMemory_3808 {
  strings:
    $key_3808 = { 6f 7a [2] 5d 58 [2] 5b 6d [2] 75 6d [2] 4a 71 }

  condition:
    any of them
}